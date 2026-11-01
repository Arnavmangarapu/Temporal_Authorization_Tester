from pathlib import Path

import pytest
import yaml


@pytest.fixture
def example_path() -> Path:
    return Path(__file__).resolve().parents[1] / "examples" / "document-lab.yaml"


@pytest.fixture
def config_data(example_path: Path) -> dict:
    return yaml.safe_load(example_path.read_text(encoding="utf-8"))
