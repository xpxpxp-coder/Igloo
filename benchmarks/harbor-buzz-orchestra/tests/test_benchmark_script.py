"""The benchmark wrapper must preserve immutable Snowman evidence inputs."""

import importlib.util
import sys
from pathlib import Path

import pytest


_SCRIPT = Path(__file__).parent.parent / "scripts" / "benchmark.py"
_spec = importlib.util.spec_from_file_location("snowman_benchmark", _SCRIPT)
benchmark = importlib.util.module_from_spec(_spec)
sys.modules["snowman_benchmark"] = benchmark
_spec.loader.exec_module(benchmark)


def test_requires_content_addressed_command_center_image():
    digest_image = (
        "ghcr.io/snowman-ai-org/snowman-command-center@sha256:" + "a" * 64
    )
    assert benchmark.require_immutable_image(digest_image) == digest_image

    for value in (
        None,
        "",
        "image:main",
        "image:sha-1234567",
        "image@sha256:ABC",
        "ghcr.io/block/buzz@sha256:" + "a" * 64,
        "registry.external.example/command-center@sha256:" + "a" * 64,
    ):
        with pytest.raises(SystemExit, match="BUZZ_IMAGE"):
            benchmark.require_immutable_image(value)
