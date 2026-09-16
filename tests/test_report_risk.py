from types import SimpleNamespace

from workflows.report_workflow import ReportWorkflow


def test_medium_web_risk_cannot_be_downgraded_to_low():
    reports = {
        "web": SimpleNamespace(risk="Medium"),
        "network": SimpleNamespace(risk="Low"),
    }

    assert (
        ReportWorkflow._enforce_overall_risk("Low", reports)
        == "MEDIUM"
    )


def test_high_component_risk_cannot_be_downgraded():
    reports = {
        "web": SimpleNamespace(risk="High"),
        "network": SimpleNamespace(risk="Medium"),
    }

    assert (
        ReportWorkflow._enforce_overall_risk("Low", reports)
        == "HIGH"
    )


def test_critical_component_risk_wins():
    reports = {
        "web": SimpleNamespace(risk="Critical"),
    }

    assert (
        ReportWorkflow._enforce_overall_risk("Medium", reports)
        == "CRITICAL"
    )


def test_ai_higher_risk_cannot_override_verified_component_risk():
    reports = {
        "web": SimpleNamespace(risk="Medium"),
        "network": SimpleNamespace(risk="Low"),
    }

    assert (
        ReportWorkflow._enforce_overall_risk("High", reports)
        == "MEDIUM"
    )


def test_ai_risk_cannot_raise_verified_component_risk():
    reports = {
        "web": SimpleNamespace(risk="Low"),
    }

    assert (
        ReportWorkflow._enforce_overall_risk("low to medium", reports)
        == "LOW"
    )


def test_incomplete_assessment_forces_undetermined_risk():
    workflow = ReportWorkflow.__new__(ReportWorkflow)

    exec_result = SimpleNamespace(
        success=True,
        data={
            "response": SimpleNamespace(
                analysis=SimpleNamespace(
                    summary="Assessment summary",
                    business_impact="Unknown",
                    technical_impact="Unknown",
                    overall_risk="CRITICAL",
                    priorities=[],
                    next_actions=[],
                )
            )
        },
        errors=[],
    )

    document = workflow._format_document(
        "http://scanme.nmap.org",
        {
            "web": SimpleNamespace(
                risk="Critical",
                executive_summary="Web assessment",
            ),
            "network": SimpleNamespace(
                risk="High",
                reputation="Unknown",
            ),
        },
        exec_result,
        assessment_errors=["network scan timed out"],
    )

    assert "Assessment Status: INCOMPLETE" in document
    assert (
        "Overall Risk: UNDETERMINED — assessment evidence is incomplete"
        in document
    )
    assert "network scan timed out" in document
    assert "Overall Risk: CRITICAL" not in document
