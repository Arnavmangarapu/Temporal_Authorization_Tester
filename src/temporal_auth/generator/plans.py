"""Canonical action dependencies, seeded topological ordering and valid removal."""

import random
from typing import Literal

from pydantic import BaseModel, ConfigDict

from temporal_auth.config.lifecycle import LifecycleConfig

OPTIONAL = frozenset({"warmup_old", "warmup_control"})


class Action(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    depends_on: list[str]


def catalog(config: LifecycleConfig, optional: set[str], write_order: str) -> dict[str, set[str]]:
    graph = {
        "login_owner": set(), "login_subject_discovery": set(),
        "create_resource": {"login_owner"},
        "establish_access": {"create_resource", "login_subject_discovery"},
        "login_subject_old": {"establish_access"},
        "read_before_transition": {"login_subject_old"},
    }
    before = "read_before_transition"
    if config.policy.action == "write":
        graph["setup_write"] = {before}
        graph["setup_write_readback"] = {"setup_write"}
        before = "setup_write_readback"
    if config.workflow.control != config.workflow.owner:
        graph["login_control"] = set()
    control_deps = {before, "login_control" if config.workflow.control != config.workflow.owner else "login_owner"}
    graph["control_before_transition"] = control_deps
    for node in sorted(optional):
        graph[node] = control_deps.copy()
    graph["transition"] = {"control_before_transition", *optional}
    graph["login_subject_fresh"] = {"transition"}
    graph["wait_for_deadline"] = {"login_subject_fresh"}
    if config.policy.action == "read":
        graph["probe_old"] = {"wait_for_deadline"}
        graph["probe_fresh"] = {"wait_for_deadline"}
        graph["control_after_transition"] = {"probe_old", "probe_fresh"}
    else:
        previous = "wait_for_deadline"
        for role in (("old", "fresh") if write_order == "old_first" else ("fresh", "old")):
            graph[f"baseline_{role}"] = {previous}
            graph[f"probe_{role}"] = {f"baseline_{role}"}
            graph[f"readback_{role}"] = {f"probe_{role}"}
            previous = f"readback_{role}"
        graph["control_after_transition"] = {previous}
    return graph


class Scenario(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["1"] = "1"
    seed: int
    lifecycle: Literal["sharing_revocation", "role_downgrade", "ownership_transfer"]
    action: Literal["read", "write"]
    write_order: Literal["old_first", "fresh_first"] = "old_first"
    nodes: list[Action]

    def validate_for(self, config: LifecycleConfig) -> None:
        if self.lifecycle != config.policy.lifecycle or self.action != config.policy.action:
            raise ValueError("scenario_policy_mismatch")
        if self.action == "read" and self.write_order != "old_first":
            raise ValueError("unsupported_read_order")
        ids = [node.id for node in self.nodes]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate_action")
        expected = catalog(config, set(ids) & OPTIONAL, self.write_order)
        if set(ids) != set(expected):
            raise ValueError("missing_or_unknown_action")
        done = set()
        for node in self.nodes:
            if set(node.depends_on) != expected[node.id] or len(node.depends_on) != len(set(node.depends_on)):
                raise ValueError("dependencies_changed")
            if not expected[node.id] <= done:
                raise ValueError("dependency_order_invalid")
            done.add(node.id)

    def without(self, node_id: str, config: LifecycleConfig) -> "Scenario":
        self.validate_for(config)
        if node_id not in OPTIONAL or node_id not in {node.id for node in self.nodes}:
            raise ValueError("only_optional_actions_can_be_removed")
        remaining = [node.id for node in self.nodes if node.id != node_id]
        graph = catalog(config, set(remaining) & OPTIONAL, self.write_order)
        candidate = self.model_copy(update={"nodes": [Action(id=name, depends_on=sorted(graph[name])) for name in remaining]})
        candidate.validate_for(config)
        return candidate


def generate_scenario(config: LifecycleConfig, seed: int = 0, *, warmups: bool = True) -> Scenario:
    rng = random.Random(seed)
    order = rng.choice(("old_first", "fresh_first")) if config.policy.action == "write" else "old_first"
    graph = catalog(config, set(OPTIONAL) if warmups else set(), order)
    done = set()
    nodes = []
    while len(done) < len(graph):
        eligible = sorted(name for name, deps in graph.items() if name not in done and deps <= done)
        if not eligible:
            raise ValueError("cyclic_action_graph")
        name = rng.choice(eligible)
        nodes.append(Action(id=name, depends_on=sorted(graph[name])))
        done.add(name)
    scenario = Scenario(seed=seed, lifecycle=config.policy.lifecycle, action=config.policy.action, write_order=order, nodes=nodes)
    scenario.validate_for(config)
    return scenario
