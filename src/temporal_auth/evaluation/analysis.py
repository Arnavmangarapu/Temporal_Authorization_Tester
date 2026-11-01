"""Finite-corpus counts, paired costs and explicit missing-data denominators."""

from collections import Counter, defaultdict
import csv
import json
from pathlib import Path
import statistics

from temporal_auth.evaluation.campaign import TRACKS, load_rows, work_items
from temporal_auth.integrations.pilot import private_json


def distribution(values):
    values = [v for v in values if isinstance(v, (int, float))]
    if not values: return {"n": 0, "median": None, "min": None, "max": None}
    return {"n": len(values), "median": statistics.median(values), "min": min(values), "max": max(values)}


def case_results(rows, cases):
    by_case = defaultdict(list)
    for row in rows: by_case[row["case"]].append(row["observed"])
    results = []
    for identifier, observations in sorted(by_case.items()):
        case = cases[identifier]
        expected = {"violation": "confirmed_violation", "correct": "no_violation_observed", "inconclusive": "inconclusive"}[case["truth"]]
        results.append({"case": identifier, "truth": case["truth"], "root_cause": case["root_cause"],
            "repeats": len(observations), "expected_verdict": expected,
            "verdicts": dict(Counter(o["verdict"] for o in observations)),
            "correctly_classified": sum(o["verdict"] == expected for o in observations),
            "confirmed_any": any(o["verdict"] == "confirmed_violation" for o in observations),
            "confirmed_every": all(o["verdict"] == "confirmed_violation" for o in observations),
            "alarm_any": any(o["verdict"] in ("confirmed_violation", "candidate") for o in observations),
            "requests": distribution([o.get("requests") for o in observations])})
    return results


def method_summary(rows, cases):
    per_case = case_results(rows, cases)
    defects = [c for c in per_case if c["truth"] == "violation"]
    correct = [c for c in per_case if c["truth"] == "correct"]
    uncertain = [c for c in per_case if c["truth"] == "inconclusive"]
    attempts = [a for r in rows for a in r["observed"].get("attempt_details", [])]
    return {"runs": len(rows), "case_configurations": len(per_case),
        "statuses": dict(Counter(r["observed"]["status"] for r in rows)),
        "verdicts": dict(Counter(r["observed"]["verdict"] for r in rows)),
        "defect_configurations": {"denominator": len(defects), "detected_any_seed": sum(c["confirmed_any"] for c in defects),
                                  "detected_every_seed": sum(c["confirmed_every"] for c in defects)},
        "root_cause_families_detected": sorted({c["root_cause"] for c in defects if c["confirmed_any"]}),
        "correct_configurations": {"denominator": len(correct), "with_any_alarm": sum(c["alarm_any"] for c in correct),
                                   "with_any_confirmed_alarm": sum(c["confirmed_any"] for c in correct)},
        "expected_inconclusive_configurations": {"denominator": len(uncertain),
            "correct_every_seed": sum(c["correctly_classified"] == c["repeats"] for c in uncertain)},
        "sequences": {"collected": len(attempts), "completed": sum(a["collection_status"] == "completed" for a in attempts),
                      "oracle_valid": sum(a["verdict"] != "inconclusive" for a in attempts)},
        "replay": {"attempted": sum(a["phase"] == "replay" for a in attempts),
                   "matching_reproductions": sum(r["observed"].get("reproductions", 0) for r in rows)},
        "requests_by_truth": {truth: distribution([r["observed"].get("requests") for r in rows if cases[r["case"]]["truth"] == truth])
                              for truth in ("correct", "violation", "inconclusive")},
        "wall_seconds": distribution([r["observed"].get("wall_seconds") for r in rows]), "per_case": per_case}


def analyze(protocol, output):
    output = Path(output)
    rows = load_rows(output, protocol)
    cases = {case["id"]: case for case in protocol["cases"]}
    report = {"scope": protocol["scope"], "protocol_sha256": protocol["protocol_sha256"],
        "corpus_status": protocol["corpus_status"], "analysis_units": protocol["analysis_units"],
        "coverage": {track: {"required": len(work_items(protocol, track)), "recorded": sum(r["track"] == track for r in rows)} for track in TRACKS},
        "controlled": {}, "tcp": {}, "posthoc": {}, "external": {}, "native": []}
    report["all_frozen_rows_recorded"] = all(c["required"] == c["recorded"] for c in report["coverage"].values())
    for track, name in (("logical", "controlled"), ("tcp", "tcp")):
        selected = [r for r in rows if r["track"] == track]
        report[name] = {method: method_summary([r for r in selected if r["method"] == method], cases) for method in protocol["methods"]}
        by_pair = defaultdict(dict)
        for r in selected: by_pair[(r["case"], r["seed"])][r["method"]] = r["observed"]
        pairs = [p for p in by_pair.values() if set(p) == set(protocol["methods"])]
        report[name + "_paired"] = {"complete_pairs": len(pairs),
            "same_verdict_across_all_methods": sum(len({o["verdict"] for o in p.values()}) == 1 for p in pairs),
            "seeded_minus_minimal_requests": distribution([p["seeded-dag"]["requests"] - p["seeded-minimal"]["requests"] for p in pairs
                                                           if all(isinstance(p[m].get("requests"), int) for m in protocol["methods"])])}
    full = [r for r in rows if r["track"] == "logical" and r["method"] == "seeded-dag"]
    for projection in ("old-only", "fresh-only", "status-only"):
        projected = [(cases[r["case"]], r["observed"]["posthoc"][projection]) for r in full if "posthoc" in r["observed"]]
        report["posthoc"][projection] = {"scope": "Retrospective signal sensitivity; no independently executed baseline or saved-query claim",
            "runs": len(projected), "signals_on_defective_runs": sum(c["truth"] == "violation" and o["verdict"] in ("candidate", "confirmed_violation") for c, o in projected),
            "defective_run_denominator": sum(c["truth"] == "violation" for c, o in projected),
            "signals_on_correct_runs": sum(c["truth"] == "correct" and o["verdict"] in ("candidate", "confirmed_violation") for c, o in projected),
            "correct_run_denominator": sum(c["truth"] == "correct" for c, o in projected),
            "confirmation_selection_bias": "Only full-method candidates have two clean replays available in this projection"}
    early = [r["observed"] for r in rows if r["track"] == "early"]
    report["early_diagnostic"] = {"traces": len(early), "unsafe_signals_on_correct_delayed_fixtures": sum(o.get("unsafe_early_claim") == "candidate" for o in early),
        "production_oracle_inconclusive": sum(o["verdict"] == "inconclusive" for o in early),
        "production_oracle_reasons": dict(Counter(o.get("reason", o.get("error")) for o in early)),
        "scope": "No clean confirmation; early access is permitted by policy and is not a defect"}
    reduced = [r["observed"] for r in rows if r["track"] == "minimize"]
    report["minimization"] = {"runs": len(reduced), "completed": sum(o.get("reduction", {}).get("status") == "completed" for o in reduced),
        "action_reduction": distribution([o["reduction"]["before_actions"] - o["reduction"]["after_actions"] for o in reduced if "reduction" in o]),
        "search_requests": distribution([o["reduction"]["search_requests"] for o in reduced if "reduction" in o]),
        "scope": "Greedy deletion of two optional warmups; production reducer independently confirms accepted reductions"}
    for target in protocol["tracks"]["external"]["targets"]:
        report["external"][target] = {}
        for profile in protocol["tracks"]["external"]["profiles"]:
            selected = [r["observed"] for r in rows if r["track"] == "external" and r["case"] == target and r["method"] == profile]
            report["external"][target][profile] = {"runs": len(selected), "statuses": dict(Counter(o["status"] for o in selected)),
                "verdicts": dict(Counter(o["verdict"] for o in selected)), "requests": distribution([o.get("total_requests") for o in selected]),
                "elapsed_seconds": distribution([o.get("elapsed_seconds") for o in selected]), "natural_defect_recall": None}
    report["native"] = [{"target": r["case"], "method": r["method"], **r["observed"]} for r in rows if r["track"] == "native"]
    report["harness_errors"] = [{"key": r["key"], "error": r["observed"].get("error")} for r in rows if r["observed"]["status"] == "harness_error"]
    report["research_readiness"] = {"held_out_defect_families": False, "independent_mutation_review": False,
        "matched_native_tool_effectiveness": False, "novelty_cleared": False,
        "scope": "Completion of an artifact campaign does not complete the broader publication-readiness gates"}
    private_json(output / "analysis.json", report)
    with (output / "runs.csv").open("w", newline="") as stream:
        columns = ["track", "case", "method", "seed", "truth", "status", "verdict", "requests", "fixture_requests", "timing", "evidence"]
        writer = csv.DictWriter(stream, fieldnames=columns); writer.writeheader()
        for r in rows:
            o = r["observed"]
            writer.writerow({"track": r["track"], "case": r["case"], "method": r["method"], "seed": r["seed"],
                "truth": cases.get(r["case"], {}).get("truth", "unknown-natural-denominator"), "status": o["status"], "verdict": o["verdict"],
                "requests": o.get("requests", o.get("total_requests")), "fixture_requests": o.get("fixture_requests"),
                "timing": o.get("timing", "real-monotonic"), "evidence": r["evidence"]})
    return report


def markdown(report):
    lines = ["**Frozen artifact evaluation**", "", report["scope"], "", report["corpus_status"], "",
        f"Protocol SHA-256: `{report['protocol_sha256']}`. Raw row coverage complete: **{report['all_frozen_rows_recorded']}**.", "",
        "Repeated seeds are not independent defects. Logical-clock durations are not runtime measurements.", "",
        "| Method | Runs | Defective configurations found (any seed) | Correct configurations with any alarm | Root-cause families |",
        "|---|---:|---:|---:|---:|"]
    for method, value in report["controlled"].items():
        d, c = value["defect_configurations"], value["correct_configurations"]
        lines.append(f"| {method} | {value['runs']} | {d['detected_any_seed']}/{d['denominator']} | {c['with_any_alarm']}/{c['denominator']} | {len(value['root_cause_families_detected'])} |")
    p = report["controlled_paired"]
    lines += ["", f"Identical verdicts across scheduling methods: {p['same_verdict_across_all_methods']}/{p['complete_pairs']} complete paired runs.",
        "", "Native application profiles use two existing codebases with unknown natural-defect denominators. No natural-defect recall is computed.", "",
        "RESTler/EvoMaster results are compatibility checks with unequal lifecycle inputs and native oracles. They are not effectiveness rankings.", "",
        "Post-hoc single-session/status projections reuse full-method traces; their signals are not independently executed P4/fuzzer results or query savings.", "",
        "The early diagnostic deliberately skips the legitimate grace period. Its signals on correct delayed fixtures are unsafe candidate claims, not defects.", "",
        "Publication readiness remains open: held-out defect families, independent review, matched native-tool experiments and a defensible novelty claim are not established.", ""]
    return "\n".join(lines)
