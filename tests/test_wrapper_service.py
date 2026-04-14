from __future__ import annotations

from suscheck.services.wrapper_service import (
    build_clone_failure_message,
    build_connect_result_panel,
    build_install_failure_message,
    execute_clone_wrapper,
    execute_install_wrapper,
    normalize_install_ecosystem,
)


def test_normalize_install_ecosystem() -> None:
    assert normalize_install_ecosystem("pip") == "pypi"
    assert normalize_install_ecosystem("PyPi") == "pypi"
    assert normalize_install_ecosystem("npm") == "npm"
    assert normalize_install_ecosystem("gem") is None


def test_execute_install_wrapper_delegates(monkeypatch) -> None:
    monkeypatch.setattr(
        "suscheck.services.wrapper_service.install_package",
        lambda ecosystem, package: 7,
    )
    assert execute_install_wrapper(trust_ecosystem="pypi", package="requests") == 7


def test_execute_clone_wrapper_delegates(monkeypatch) -> None:
    monkeypatch.setattr(
        "suscheck.services.wrapper_service.clone_repo",
        lambda url, dest: 3,
    )
    assert execute_clone_wrapper(url="https://example.com/repo.git", dest=None) == 3


def test_failure_messages() -> None:
    assert "not found" in build_install_failure_message(127).lower()
    assert "status code 5" in build_install_failure_message(5)
    assert "not found" in build_clone_failure_message(127).lower()
    assert "status code 9" in build_clone_failure_message(9)


def test_build_connect_result_panel_force(monkeypatch) -> None:
    monkeypatch.setattr(
        "suscheck.services.wrapper_service.connect_mcp",
        lambda target, pri_score, force=False: {"target": target, "pri_score": pri_score, "can_proceed": True},
    )

    panel = build_connect_result_panel(
        server="http://localhost:11434",
        pri_score=31,
        verdict_label="CAUTION",
        force=True,
    )

    assert panel.border_style == "red"


def test_build_connect_result_panel_non_force() -> None:
    panel = build_connect_result_panel(
        server="http://localhost:11434",
        pri_score=12,
        verdict_label="CLEAR",
        force=False,
    )

    assert panel.border_style == "green"