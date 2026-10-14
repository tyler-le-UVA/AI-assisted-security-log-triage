import importlib.util
import os
import pathlib

import pytest

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "test")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")
os.environ.setdefault("TABLE_NAME", "test-table")
os.environ.setdefault("MODEL_ID", "test-model")

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def tp():
    return _load("triage_parser", "lambda/parser.py")


@pytest.fixture(scope="session")
def ev():
    return _load("prompt_eval", "eval/prompt_eval.py")
