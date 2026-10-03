"""
Regression tests for per-user/per-target active-scan grants.
"""

import services.active.auth as active_auth


def setup_function():
    active_auth.AUTHORIZED_SCAN_TARGETS.clear()
    active_auth.AUTHORIZED_SCAN_GRANTS.clear()


def teardown_function():
    active_auth.AUTHORIZED_SCAN_TARGETS.clear()
    active_auth.AUTHORIZED_SCAN_GRANTS.clear()


def test_grant_allows_user_for_authorized_target():
    user_id = 200001
    active_auth.AUTHORIZED_SCAN_TARGETS.add("example.com")

    assert active_auth.is_authorized(user_id, "https://example.com")[0] is False

    assert active_auth.grant_scan_access(
        user_id,
        "https://example.com",
        granted_by=999001,
    ) is True

    allowed, reason = active_auth.is_authorized(
        user_id,
        "https://example.com",
    )

    assert allowed is True
    assert "explicit_user_target_grant" in reason


def test_grant_does_not_allow_other_target():
    user_id = 200002
    active_auth.AUTHORIZED_SCAN_TARGETS.update(
        {"example.com", "other-example.invalid"}
    )

    active_auth.grant_scan_access(
        user_id,
        "example.com",
        granted_by=999001,
    )

    allowed, reason = active_auth.is_authorized(
        user_id,
        "other-example.invalid",
    )

    assert allowed is False
    assert "not authorized to scan target" in reason


def test_revoke_removes_specific_grant():
    user_id = 200003
    active_auth.AUTHORIZED_SCAN_TARGETS.add("example.com")

    active_auth.grant_scan_access(
        user_id,
        "example.com",
        granted_by=999001,
    )

    assert active_auth.is_authorized(user_id, "example.com")[0] is True

    assert active_auth.revoke_scan_access(
        user_id,
        "example.com",
        revoked_by=999001,
    ) is True

    assert active_auth.is_authorized(user_id, "example.com")[0] is False


def test_grant_requires_global_target_authorization():
    user_id = 200004

    assert active_auth.grant_scan_access(
        user_id,
        "not-authorized.invalid",
        granted_by=999001,
    ) is False

    assert (user_id, "not-authorized.invalid") not in (
        active_auth.AUTHORIZED_SCAN_GRANTS
    )


def test_existing_global_user_authorization_still_works():
    user_id = 200005
    active_auth.AUTHORIZED_SCAN_USERS.add(user_id)
    active_auth.AUTHORIZED_SCAN_TARGETS.add("example.com")

    allowed, reason = active_auth.is_authorized(
        user_id,
        "example.com",
    )

    assert allowed is True
    assert "global_user_authorization" in reason
