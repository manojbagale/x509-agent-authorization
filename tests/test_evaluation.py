import pytest

from agent_auth.evaluation import EVALUATION_MODES, evaluate, evaluate_mode
from agent_auth.experiment import MODES, run_mode
from agent_auth.gateway import AuthorizationGateway
from agent_auth.pki import ResearchCA


def test_evaluation_denominators_raw_samples_and_rotating_order():
    result = evaluate(runs=2, iterations=10, warmup=2)
    assert result["metadata"]["starting_git_sha"]
    assert len(result["runs"]) == 2 * len(EVALUATION_MODES)
    first = [r["mode"] for r in result["runs"] if r["run"] == 1]
    second = [r["mode"] for r in result["runs"] if r["run"] == 2]
    assert second == first[1:] + first[:1]
    for row in result["runs"]:
        counts = row["correctness"]
        assert counts["expected_allows"] == 3
        assert counts["expected_denies"] == 7
        assert counts["total"] == len(counts["cases"]) == 10
        assert counts["false_allows"] == counts["false_denies"] == 0
        assert len(row["raw_samples_ms"]["authorization_audit_included"]) == 10
        issuance_key = "token_registry_issuance" if row["mode"] == "token" else "certificate_leaf_issuance"
        assert len(row["raw_samples_ms"][issuance_key]) == 10
        assert row[issuance_key]["samples"] == 10
        for trial in row["revocation_trials"]:
            assert trial["precondition_allowed"] is True
            assert trial["after_allowed"] is False
            assert trial["reason"] == "session_revoked"
            assert trial["mutation_start_to_first_denial_ms"] >= trial["commit_to_first_denial_ms"] >= 0


@pytest.mark.parametrize("mode", MODES)
def test_legacy_experiment_restores_permission_before_revocation(mode, monkeypatch):
    original_kill = AuthorizationGateway.kill
    checked = []
    def check_allowed_then_kill(gateway, session):
        allowed, _ = gateway.authorize(session, {"tool": "file", "action": "read", "resource": "/research/paper.pdf"})
        assert allowed is True
        checked.append(True)
        original_kill(gateway, session)
    monkeypatch.setattr(AuthorizationGateway, "kill", check_allowed_then_kill)
    result = run_mode(mode, iterations=1)
    assert result["kill_result"] == "session_revoked"
    assert checked == [True]


@pytest.mark.parametrize("kwargs", [{"runs": 0}, {"iterations": 0}, {"warmup": -1}])
def test_evaluation_rejects_invalid_counts(kwargs):
    with pytest.raises(ValueError):
        evaluate(**kwargs)


def test_correctness_failure_aborts_evaluation(monkeypatch):
    monkeypatch.setattr(AuthorizationGateway, "authorize", lambda *args: (False, "injected_error"))
    with pytest.raises(AssertionError, match="correctness matrix failed"):
        evaluate_mode("certificate", ca=ResearchCA.create(), iterations=1, warmup=0)
