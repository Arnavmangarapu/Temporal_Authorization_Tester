import json
import math

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from temporal_auth.cli import app
from temporal_auth.config import ConfigLoadError, TargetConfig, load_config
from temporal_auth.config.models import KnownTiming, UnknownTiming


def test_example_loads_without_resolving_passwords(example_path, monkeypatch):
    monkeypatch.delenv("LAB_ALICE_PASSWORD", raising=False)
    monkeypatch.delenv("LAB_BOB_PASSWORD", raising=False)
    config = load_config(example_path)
    assert config.workflow.owner == config.workflow.control == "alice"
    assert config.workflow.subject == "bob"
    assert isinstance(config.policy.timing, KnownTiming)
    assert config.policy.timing.max_delay_seconds == 5


def test_unknown_timing_remains_explicit(config_data):
    config_data["policy"]["timing"] = {"mode": "unknown", "reason": "No documented bound."}
    config = TargetConfig.model_validate(config_data)
    assert isinstance(config.policy.timing, UnknownTiming)
    assert not hasattr(config.policy.timing, "max_delay_seconds")


def test_immediate_revocation_is_a_valid_policy(config_data):
    config_data["policy"]["timing"]["max_delay_seconds"] = 0
    assert TargetConfig.model_validate(config_data).policy.timing.max_delay_seconds == 0


@pytest.mark.parametrize("bad_bound", [-1, math.inf, -math.inf, math.nan, True, "5"])
def test_invalid_time_bounds_cannot_silently_change_policy(config_data, bad_bound):
    config_data["policy"]["timing"]["max_delay_seconds"] = bad_bound
    with pytest.raises(ValidationError):
        TargetConfig.model_validate(config_data)


@pytest.mark.parametrize("field", ["source", "max_delay_seconds"])
def test_bounded_timing_requires_explicit_source_and_bound(config_data, field):
    del config_data["policy"]["timing"][field]
    with pytest.raises(ValidationError):
        TargetConfig.model_validate(config_data)


def test_missing_timing_cannot_default_to_immediate(config_data):
    del config_data["policy"]["timing"]
    with pytest.raises(ValidationError):
        TargetConfig.model_validate(config_data)


def test_unknown_timing_cannot_also_supply_a_bound(config_data):
    config_data["policy"]["timing"] = {
        "mode": "unknown", "reason": "Undocumented", "max_delay_seconds": 0,
    }
    with pytest.raises(ValidationError):
        TargetConfig.model_validate(config_data)


def test_unobservable_effective_time_is_not_accepted_as_acknowledgement(config_data):
    config_data["policy"]["timing"]["anchor"] = "policy_committed"
    with pytest.raises(ValidationError):
        TargetConfig.model_validate(config_data)


@pytest.mark.parametrize("actor_role", ["owner", "subject", "control"])
def test_workflow_actor_references_exist(config_data, actor_role):
    config_data["workflow"][actor_role] = "missing_actor"
    with pytest.raises(ValidationError, match="undefined actor"):
        TargetConfig.model_validate(config_data)


@pytest.mark.parametrize("actor_role", ["owner", "control"])
def test_subject_cannot_be_used_as_its_own_authorized_control(config_data, actor_role):
    config_data["workflow"][actor_role] = "bob"
    with pytest.raises(ValidationError, match="subject must differ"):
        TargetConfig.model_validate(config_data)


def test_actor_aliases_cannot_hide_a_single_account(config_data):
    config_data["actors"]["bob"]["username"] = "alice"
    with pytest.raises(ValidationError, match="different usernames"):
        TargetConfig.model_validate(config_data)


@pytest.mark.parametrize("operation_role", ["create_resource", "grant_access", "revoke_access", "read_resource"])
def test_workflow_operation_references_exist(config_data, operation_role):
    config_data["workflow"]["operations"][operation_role] = "missing_operation"
    with pytest.raises(ValidationError, match="undefined operation"):
        TargetConfig.model_validate(config_data)


def test_authentication_operation_reference_exists(config_data):
    config_data["authentication"]["login_operation"] = "missing_login"
    with pytest.raises(ValidationError, match="undefined operation"):
        TargetConfig.model_validate(config_data)


@pytest.mark.parametrize("operation", ["login", "create_document", "grant_share", "revoke_share"])
def test_mutating_operations_cannot_be_mistaken_for_read_requests(config_data, operation):
    config_data["operations"][operation]["method"] = "GET"
    with pytest.raises(ValidationError):
        TargetConfig.model_validate(config_data)


def test_read_operation_must_be_read_only(config_data):
    config_data["operations"]["read_document"]["method"] = "DELETE"
    with pytest.raises(ValidationError, match="read_resource"):
        TargetConfig.model_validate(config_data)


@pytest.mark.parametrize("base_url", [
    "http://alice:password@example.test", "http://example.test/api",
    "http://example.test?token=secret", "http://example.test#fragment", "file:///tmp/target",
])
def test_base_url_is_an_http_origin_without_embedded_credentials(config_data, base_url):
    config_data["base_url"] = base_url
    with pytest.raises(ValidationError):
        TargetConfig.model_validate(config_data)


@pytest.mark.parametrize("path", ["documents", "//another.test/documents", "https://another.test/x", "/x?token=secret", "/x#fragment"])
def test_operations_use_application_relative_paths(config_data, path):
    config_data["operations"]["read_document"]["path"] = path
    with pytest.raises(ValidationError):
        TargetConfig.model_validate(config_data)


@pytest.mark.parametrize("field,value", [
    ("max_requests", 0), ("max_requests", True), ("max_runtime_seconds", 0),
    ("poll_interval_seconds", 0), ("request_timeout_seconds", -1),
    ("request_timeout_seconds", 601),
])
def test_budgets_must_allow_bounded_execution(config_data, field, value):
    config_data["budget"][field] = value
    with pytest.raises(ValidationError):
        TargetConfig.model_validate(config_data)


def test_budget_must_extend_past_deadline(config_data):
    config_data["budget"]["max_runtime_seconds"] = 5.05
    config_data["budget"]["request_timeout_seconds"] = 1
    with pytest.raises(ValidationError, match="probe after"):
        TargetConfig.model_validate(config_data)


@pytest.mark.parametrize("pointer", ["content", "/bad~escape"])
def test_protected_field_is_a_json_pointer(config_data, pointer):
    config_data["workflow"]["protected_field"] = pointer
    with pytest.raises(ValidationError):
        TargetConfig.model_validate(config_data)


def test_unsupported_lifecycle_does_not_look_implemented(config_data):
    config_data["policy"]["lifecycle"] = "role_downgrade"
    with pytest.raises(ValidationError):
        TargetConfig.model_validate(config_data)


def test_literal_password_is_rejected_without_echoing_value(config_data, tmp_path):
    import yaml

    secret = "do-not-print-this-value"
    config_data["actors"]["alice"]["password"] = secret
    path = tmp_path / "bad.yaml"
    path.write_text(yaml.safe_dump(config_data), encoding="utf-8")
    with pytest.raises(ConfigLoadError) as error:
        load_config(path)
    assert "Extra inputs" in str(error.value)
    assert secret not in str(error.value)


@pytest.mark.parametrize("contents", [
    "name: first\nname: second\n",
    "policy:\n  timing:\n    max_delay_seconds: 0\n    max_delay_seconds: 5\n",
    "!!python/object/apply:os.system ['echo unsafe']",
    "name: [broken-secret-value\n",
])
def test_ambiguous_or_unsafe_yaml_is_rejected(contents, tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text(contents, encoding="utf-8")
    with pytest.raises(ConfigLoadError, match="Invalid YAML") as error:
        load_config(path)
    assert "broken-secret-value" not in str(error.value)


@pytest.mark.parametrize("contents", ["", "- alice\n- bob\n", "a string\n"])
def test_configuration_root_must_be_a_mapping(contents, tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text(contents, encoding="utf-8")
    with pytest.raises(ConfigLoadError, match="mapping"):
        load_config(path)


def test_unreadable_configuration_is_reported(tmp_path):
    with pytest.raises(ConfigLoadError, match="Cannot read"):
        load_config(tmp_path / "missing.yaml")


def test_cli_validation_makes_its_scope_clear(example_path):
    result = CliRunner().invoke(app, ["validate", str(example_path)])
    assert result.exit_code == 0
    assert "Revocation bound: 5s" in result.stdout
    assert "no application was contacted or tested" in result.stdout


def test_cli_invalid_configuration_has_nonzero_exit(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("name: first\nname: second\n", encoding="utf-8")
    result = CliRunner().invoke(app, ["validate", str(path)])
    assert result.exit_code == 2
    assert "Invalid YAML" in result.output


def test_cli_warns_when_temporal_policy_is_unknown(config_data, tmp_path):
    import yaml

    config_data["policy"]["timing"] = {"mode": "unknown", "reason": "Undocumented."}
    path = tmp_path / "unknown.yaml"
    path.write_text(yaml.safe_dump(config_data), encoding="utf-8")
    result = CliRunner().invoke(app, ["validate", str(path)])
    assert result.exit_code == 0
    assert "must be inconclusive" in result.stdout


def test_schema_command_exports_the_discriminated_timing_contract():
    result = CliRunner().invoke(app, ["schema"])
    assert result.exit_code == 0
    schema = json.loads(result.stdout)
    assert schema["$defs"]["RevocationPolicy"]["properties"]["timing"]["discriminator"]["propertyName"] == "mode"
