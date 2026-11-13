import pytest
from uuid import uuid4

from app.auth import create_access_token, decode_access_token, hash_password, verify_password


def _response_payload(response):
    import json
    from starlette.responses import JSONResponse

    if isinstance(response, JSONResponse):
        return json.loads(response.body)
    return response


async def _register_verified_account(db_session, monkeypatch, email, password):
    from urllib.parse import urlparse, parse_qs
    import app.main as main
    from app.schemas import AuthRegisterRequest, ActionTokenRequest, AuthLoginRequest
    messages = []
    async def fake_send_email(recipient, subject, body):
        messages.append(body)
    monkeypatch.setattr(main, "send_email", fake_send_email)
    await main.register_account(AuthRegisterRequest(email=email, password=password), db_session)
    link = next(line for line in messages[-1].splitlines() if "token=" in line)
    token = parse_qs(urlparse(link).fragment)["token"][0]
    await main.verify_email(ActionTokenRequest(token=token), db_session)
    return _response_payload(await main.login_account(AuthLoginRequest(email=email, password=password), db_session))




def test_password_hash_uses_salted_pbkdf2_and_verifies():
    encoded = hash_password("correct horse battery staple")
    assert encoded.startswith("pbkdf2_sha256$600000$")
    assert verify_password("correct horse battery staple", encoded)
    assert not verify_password("incorrect password", encoded)
    assert hash_password("correct horse battery staple") != encoded


def test_access_token_round_trip_and_tamper_detection(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "auth_secret", "test-secret-that-is-long-enough-for-hmac-256")
    user_id = uuid4()
    token = create_access_token(user_id)
    assert decode_access_token(token) == user_id
    header, payload, signature = token.split(".")
    tampered = f"{header}.{payload}.{chr(ord(signature[0]) ^ 1)}{signature[1:]}"
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as error:
        decode_access_token(tampered)
    assert error.value.status_code == 401


def test_auth_secret_must_be_configured(monkeypatch):
    from app.config import settings
    from fastapi import HTTPException
    monkeypatch.setattr(settings, "auth_secret", None)
    with pytest.raises(HTTPException) as error:
        create_access_token(uuid4())
    assert error.value.status_code == 503


@pytest.mark.asyncio
async def test_cookie_login_issues_httponly_tokens_without_exposing_them(db_session, monkeypatch):
    import json
    from starlette.requests import Request
    from app.config import settings
    import app.main as main
    from app.models import User
    from app.schemas import AuthLoginRequest

    monkeypatch.setattr(settings, "auth_secret", "test-secret-that-is-long-enough-for-hmac-256")
    user = User(email="cookie-login@example.com", password_hash=hash_password("cookie auth password"),
        is_email_verified=True)
    db_session.add(user)
    await db_session.flush()
    request = Request({
        "type": "http", "method": "POST", "path": "/v1/auth/login",
        "headers": [(b"x-editflow-cookie-auth", b"1")],
        "query_string": b"", "server": ("testserver", 80), "client": ("127.0.0.1", 1234),
        "scheme": "http",
    })
    response = await main.login_account(
        AuthLoginRequest(email=user.email, password="cookie auth password"), db_session, request
    )
    body = json.loads(response.body)
    assert body["user"]["email"] == user.email
    assert "access_token" not in body and "refresh_token" not in body
    cookies = response.headers.getlist("set-cookie")
    assert any(cookie.startswith("editflow_access=") and "httponly" in cookie.lower() for cookie in cookies)
    assert any(cookie.startswith("editflow_refresh=") and "httponly" in cookie.lower() for cookie in cookies)
    assert any(cookie.startswith("editflow_csrf=") and "httponly" not in cookie.lower() for cookie in cookies)


@pytest.mark.asyncio
async def test_access_cookie_authenticates_without_bearer_header(db_session, monkeypatch):
    from starlette.requests import Request
    from app.config import settings
    from app.auth import get_current_user
    from app.models import User

    monkeypatch.setattr(settings, "auth_secret", "test-secret-that-is-long-enough-for-hmac-256")
    user = User(email="cookie-user@example.com", password_hash=hash_password("cookie auth password"))
    db_session.add(user)
    await db_session.flush()
    token = create_access_token(user.id)
    request = Request({
        "type": "http", "method": "GET", "path": "/v1/auth/me",
        "headers": [(b"cookie", f"editflow_access={token}".encode())],
        "query_string": b"", "server": ("testserver", 80), "client": ("127.0.0.1", 1234),
        "scheme": "http",
    })
    assert await get_current_user(request, None, db_session) is user


def test_cookie_authenticated_mutations_require_matching_csrf_cookie_and_header():
    from fastapi.testclient import TestClient
    import app.main as main

    client = TestClient(main.app)
    blocked = client.post("/v1/not-a-real-route", cookies={"editflow_access": "opaque-session"})
    assert blocked.status_code == 403
    accepted_past_csrf = client.post(
        "/v1/not-a-real-route",
        cookies={"editflow_access": "opaque-session", "editflow_csrf": "csrf-value"},
        headers={"X-CSRF-Token": "csrf-value"},
    )
    assert accepted_past_csrf.status_code == 404


def test_cookie_auth_cors_preflight_allows_csrf_headers():
    from fastapi.testclient import TestClient
    import app.main as main

    response = TestClient(main.app).options(
        "/v1/auth/login",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type,x-editflow-cookie-auth,x-csrf-token",
        },
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-credentials") == "true"
    allowed = response.headers.get("access-control-allow-headers", "").lower()
    assert "x-csrf-token" in allowed
    assert "x-editflow-cookie-auth" in allowed


@pytest.mark.asyncio
async def test_register_and_login_issue_tokens_for_normalized_email(db_session, monkeypatch):
    from app.config import settings
    from app.main import login_account
    from app.schemas import AuthLoginRequest

    monkeypatch.setattr(settings, "auth_secret", "test-secret-that-is-long-enough-for-hmac-256")
    monkeypatch.setattr(settings, "auth_access_token_seconds", 900)
    registered = await _register_verified_account(
        db_session, monkeypatch, "  Editor@Example.com ", "correct horse battery staple"
    )
    assert registered["user"]["email"] == "editor@example.com"
    assert len(registered["refresh_token"]) >= 32
    assert registered["token_type"] == "bearer"
    assert registered["expires_in"] == 900
    assert decode_access_token(registered["access_token"]) == __import__("uuid").UUID(registered["user"]["id"])

    logged_in = _response_payload(await login_account(
        AuthLoginRequest(email="EDITOR@example.com", password="correct horse battery staple"),
        db_session,
    ))
    assert logged_in["user"]["id"] == registered["user"]["id"]
    assert logged_in["refresh_token"] != registered["refresh_token"]
    assert decode_access_token(logged_in["access_token"]) == __import__("uuid").UUID(registered["user"]["id"])


@pytest.mark.asyncio
async def test_project_access_is_scoped_to_authenticated_owner(db_session):
    from uuid import uuid4
    from fastapi import HTTPException
    from app.main import require_owned_project
    from app.models import Project, User

    owner = User(email="owner@example.com", password_hash=hash_password("owner password long"))
    other = User(email="other@example.com", password_hash=hash_password("other password long"))
    db_session.add_all([owner, other])
    await db_session.flush()
    project = Project(title="Private project", owner_id=owner.id)
    db_session.add(project)
    await db_session.flush()

    assert await require_owned_project(
        project.id, db=db_session, current_user=owner
    ) is project

    with pytest.raises(HTTPException) as error:
        await require_owned_project(
            project.id, db=db_session, current_user=other
        )
    assert error.value.status_code == 404

    with pytest.raises(HTTPException) as missing:
        await require_owned_project(
            uuid4(), db=db_session, current_user=owner
        )
    assert missing.value.status_code == 404


@pytest.mark.asyncio
async def test_viewer_can_read_project_but_cannot_mutate(db_session):
    from uuid import uuid4
    from fastapi import HTTPException
    from app.main import require_project_access, require_project_editor
    from app.models import Project, ProjectMember, User

    owner = User(email="role-owner@example.com", password_hash=hash_password("owner password long"))
    viewer = User(email="role-viewer@example.com", password_hash=hash_password("viewer password long"))
    db_session.add_all([owner, viewer])
    await db_session.flush()
    project = Project(title="Viewer project", owner_id=owner.id)
    db_session.add(project)
    await db_session.flush()
    db_session.add(ProjectMember(project_id=project.id, user_id=viewer.id, role="viewer"))
    await db_session.flush()

    assert await require_project_access(
        project.id, db=db_session, current_user=viewer
    ) is project
    with pytest.raises(HTTPException) as error:
        await require_project_editor(
            project=project, db=db_session, current_user=viewer
        )
    assert error.value.status_code == 403


@pytest.mark.asyncio
async def test_editor_can_mutate_and_nonmember_cannot_access(db_session):
    from uuid import uuid4
    from fastapi import HTTPException
    from app.main import require_project_access, require_project_editor
    from app.models import Project, ProjectMember, User

    owner = User(email="editor-owner@example.com", password_hash=hash_password("owner password long"))
    editor = User(email="editor@example.com", password_hash=hash_password("editor password long"))
    outsider = User(email="outsider@example.com", password_hash=hash_password("outsider password long"))
    db_session.add_all([owner, editor, outsider])
    await db_session.flush()
    project = Project(title="Editor project", owner_id=owner.id)
    db_session.add(project)
    await db_session.flush()
    db_session.add(ProjectMember(project_id=project.id, user_id=editor.id, role="editor"))
    await db_session.flush()

    assert await require_project_editor(
        project=project, db=db_session, current_user=editor
    ) is project
    with pytest.raises(HTTPException) as error:
        await require_project_access(
            project.id, db=db_session, current_user=outsider
        )
    assert error.value.status_code == 404


@pytest.mark.asyncio
async def test_owner_can_assign_update_and_remove_project_member(db_session):
    from app.main import upsert_project_member, list_project_members, remove_project_member
    from app.models import Project, User
    from app.schemas import ProjectMemberUpsert

    owner = User(email="sharing-owner@example.com", password_hash=hash_password("owner password long"))
    member = User(email="sharing-user@example.com", password_hash=hash_password("member password long"))
    db_session.add_all([owner, member])
    await db_session.flush()
    project = Project(title="Shared project", owner_id=owner.id)
    db_session.add(project)
    await db_session.flush()

    assigned = await upsert_project_member(
        project.id,
        ProjectMemberUpsert(email=member.email, role="viewer"),
        db_session,
        _owned_project=project,
    )
    assert assigned["role"] == "viewer"

    updated = await upsert_project_member(
        project.id,
        ProjectMemberUpsert(email=member.email, role="editor"),
        db_session,
        _owned_project=project,
    )
    assert updated["role"] == "editor"

    members = await list_project_members(project.id, db_session, _owned_project=project)
    assert {item["role"] for item in members} == {"owner", "editor"}

    await remove_project_member(project.id, member.id, db_session, _owned_project=project)
    members = await list_project_members(project.id, db_session, _owned_project=project)
    assert [item["role"] for item in members] == ["owner"]

    from app.main import list_project_audit_events
    events = await list_project_audit_events(project.id, db_session, _owned_project=project)
    assert {event["action"] for event in events} == {
        "member.added", "member.role_changed", "member.removed"
    }
    assert {
        (event["previous_role"], event["new_role"])
        for event in events
    } == {(None, "viewer"), ("viewer", "editor"), ("editor", None)}
    assert all(event["actor_email"] == owner.email for event in events)
    assert all(event["target_email"] == member.email for event in events)


@pytest.mark.asyncio
async def test_refresh_token_rotation_and_reuse_revokes_session_family(db_session, monkeypatch):
    from app.config import settings
    from app.main import refresh_account
    from app.schemas import RefreshTokenRequest
    from fastapi import HTTPException

    monkeypatch.setattr(settings, "auth_secret", "test-secret-that-is-long-enough-for-hmac-256")
    registered = await _register_verified_account(
        db_session, monkeypatch, "rotate@example.com", "rotation password long"
    )
    rotated = _response_payload(await refresh_account(
        RefreshTokenRequest(refresh_token=registered["refresh_token"]),
        db_session,
    ))
    assert rotated["refresh_token"] != registered["refresh_token"]
    assert decode_access_token(rotated["access_token"]) == __import__("uuid").UUID(rotated["user"]["id"])

    with pytest.raises(HTTPException) as reused:
        await refresh_account(
            RefreshTokenRequest(refresh_token=registered["refresh_token"]),
            db_session,
        )
    assert reused.value.status_code == 401

    with pytest.raises(HTTPException) as family_revoked:
        await refresh_account(
            RefreshTokenRequest(refresh_token=rotated["refresh_token"]),
            db_session,
        )
    assert family_revoked.value.status_code == 401


@pytest.mark.asyncio
async def test_logout_revokes_refresh_session_family(db_session, monkeypatch):
    from app.config import settings
    from app.main import logout_account, refresh_account
    from app.schemas import RefreshTokenRequest
    from fastapi import HTTPException

    monkeypatch.setattr(settings, "auth_secret", "test-secret-that-is-long-enough-for-hmac-256")
    registered = await _register_verified_account(
        db_session, monkeypatch, "logout@example.com", "logout password long"
    )
    result = _response_payload(await logout_account(
        RefreshTokenRequest(refresh_token=registered["refresh_token"]),
        db_session,
    ))
    assert result == {"revoked": True}
    with pytest.raises(HTTPException) as revoked:
        await refresh_account(
            RefreshTokenRequest(refresh_token=registered["refresh_token"]),
            db_session,
        )
    assert revoked.value.status_code == 401


@pytest.mark.asyncio
async def test_auth_rate_limit_is_persistent_and_returns_retry_after(db_session, monkeypatch):
    from app.config import settings
    from app.rate_limit import enforce_rate_limit
    from app.models import RateLimitBucket
    from sqlalchemy import select
    from fastapi import HTTPException

    monkeypatch.setattr(settings, "auth_secret", "test-secret-that-is-long-enough-for-hmac-256")
    await enforce_rate_limit(db_session, ["login:ip:203.0.113.10"], 2, 900)
    await enforce_rate_limit(db_session, ["login:ip:203.0.113.10"], 2, 900)

    with pytest.raises(HTTPException) as limited:
        await enforce_rate_limit(db_session, ["login:ip:203.0.113.10"], 2, 900)
    assert limited.value.status_code == 429
    assert int(limited.value.headers["Retry-After"]) > 0

    rows = (await db_session.execute(select(RateLimitBucket))).scalars().all()
    assert len(rows) == 1
    assert rows[0].scope_key != "login:ip:203.0.113.10"
    assert rows[0].request_count == 3


@pytest.mark.asyncio
async def test_auth_rate_limits_are_isolated_by_scope(db_session, monkeypatch):
    from app.config import settings
    from app.rate_limit import enforce_rate_limit

    monkeypatch.setattr(settings, "auth_secret", "test-secret-that-is-long-enough-for-hmac-256")
    await enforce_rate_limit(db_session, ["login:ip:203.0.113.11"], 1, 900)
    await enforce_rate_limit(db_session, ["login:ip:203.0.113.12"], 1, 900)


@pytest.mark.asyncio
async def test_unverified_user_is_blocked_until_single_use_verification(db_session, monkeypatch):
    from urllib.parse import urlparse, parse_qs
    import app.main as main
    from app.config import settings
    from app.schemas import AuthRegisterRequest, AuthLoginRequest, ActionTokenRequest
    from fastapi import HTTPException

    monkeypatch.setattr(settings, "auth_secret", "test-secret-that-is-long-enough-for-hmac-256")
    sent = []
    async def fake_send_email(recipient, subject, body):
        sent.append(body)
    monkeypatch.setattr(main, "send_email", fake_send_email)
    await main.register_account(AuthRegisterRequest(
        email="pending@example.com", password="secure password long"
    ), db_session)
    with pytest.raises(HTTPException) as blocked:
        await main.login_account(AuthLoginRequest(
            email="pending@example.com", password="secure password long"
        ), db_session)
    assert blocked.value.status_code == 401
    link = next(line for line in sent[0].splitlines() if "token=" in line)
    token = parse_qs(urlparse(link).fragment)["token"][0]
    assert await main.verify_email(ActionTokenRequest(token=token), db_session) == {"verified": True}
    with pytest.raises(HTTPException) as replay:
        await main.verify_email(ActionTokenRequest(token=token), db_session)
    assert replay.value.status_code == 400


@pytest.mark.asyncio
async def test_password_reset_revokes_sessions_and_token_cannot_be_reused(db_session, monkeypatch):
    from urllib.parse import urlparse, parse_qs
    import app.main as main
    from app.config import settings
    from app.schemas import EmailOnlyRequest, PasswordResetRequest, AuthLoginRequest, RefreshTokenRequest
    from fastapi import HTTPException

    monkeypatch.setattr(settings, "auth_secret", "test-secret-that-is-long-enough-for-hmac-256")
    session = await _register_verified_account(
        db_session, monkeypatch, "reset-user@example.com", "old secure password"
    )
    sent = []
    async def fake_send_email(recipient, subject, body):
        sent.append(body)
    monkeypatch.setattr(main, "send_email", fake_send_email)
    await main.request_password_reset(EmailOnlyRequest(email="reset-user@example.com"), db_session)
    link = next(line for line in sent[0].splitlines() if "token=" in line)
    token = parse_qs(urlparse(link).fragment)["token"][0]
    assert await main.reset_password(
        PasswordResetRequest(token=token, new_password="new secure password"),
        db_session,
    ) == {"password_reset": True, "sessions_revoked": True}
    with pytest.raises(HTTPException) as replay:
        await main.reset_password(
            PasswordResetRequest(token=token, new_password="another secure password"),
            db_session,
        )
    assert replay.value.status_code == 400
    with pytest.raises(HTTPException) as old_session:
        await main.refresh_account(RefreshTokenRequest(
            refresh_token=session["refresh_token"]
        ), db_session)
    assert old_session.value.status_code == 401
    with pytest.raises(HTTPException) as old_password:
        await main.login_account(AuthLoginRequest(
            email="reset-user@example.com", password="old secure password"
        ), db_session)
    assert old_password.value.status_code == 401
    new_session = _response_payload(await main.login_account(AuthLoginRequest(
        email="reset-user@example.com", password="new secure password"
    ), db_session))
    assert new_session["user"]["email"] == "reset-user@example.com"


@pytest.mark.asyncio
async def test_invitation_is_bound_to_verified_email_and_single_use(db_session, monkeypatch):
    from urllib.parse import urlparse, parse_qs
    import app.main as main
    from app.config import settings
    from app.models import Project, ProjectMember, User
    from app.schemas import ProjectInvitationCreate, ActionTokenRequest
    from sqlalchemy import select
    from fastapi import HTTPException

    monkeypatch.setattr(settings, "auth_secret", "test-secret-that-is-long-enough-for-hmac-256")
    owner = User(email="project-owner@example.com", password_hash=hash_password("owner password long"), is_email_verified=True)
    invitee = User(email="invitee@example.com", password_hash=hash_password("invitee password long"), is_email_verified=True)
    impostor = User(email="impostor@example.com", password_hash=hash_password("impostor password long"), is_email_verified=True)
    db_session.add_all([owner, invitee, impostor])
    await db_session.flush()
    project = Project(title="Invite test", owner_id=owner.id)
    db_session.add(project)
    await db_session.flush()
    sent = []
    async def fake_send_email(recipient, subject, body):
        sent.append((recipient, body))
    monkeypatch.setattr(main, "send_email", fake_send_email)
    await main.create_project_invitation(
        project.id, ProjectInvitationCreate(email=invitee.email, role="editor"),
        db_session, _owned_project=project,
    )
    assert sent[0][0] == invitee.email
    link = next(line for line in sent[0][1].splitlines() if "token=" in line)
    token = parse_qs(urlparse(link).fragment)["token"][0]
    with pytest.raises(HTTPException) as mismatch:
        await main.accept_project_invitation(
            ActionTokenRequest(token=token), db_session, current_user=impostor
        )
    assert mismatch.value.status_code == 403
    result = await main.accept_project_invitation(
        ActionTokenRequest(token=token), db_session, current_user=invitee
    )
    assert result["accepted"] is True and result["role"] == "editor"
    member = await db_session.scalar(select(ProjectMember).where(
        ProjectMember.project_id == project.id, ProjectMember.user_id == invitee.id
    ))
    assert member.role == "editor"
    with pytest.raises(HTTPException) as replay:
        await main.accept_project_invitation(
            ActionTokenRequest(token=token), db_session, current_user=invitee
        )
    assert replay.value.status_code == 400



@pytest.mark.asyncio
async def test_legacy_project_claim_is_dry_run_by_default_and_audited_on_apply(db_session):
    from app.models import Project, ProjectAuditEvent, User
    from scripts.claim_legacy_project import claim_legacy_project

    owner = User(email="legacy-owner@example.com", password_hash=hash_password("long enough password"), is_email_verified=True)
    project = Project(title="Imported legacy project", owner_id=None)
    db_session.add_all([owner, project])
    await db_session.flush()
    project_id = project.id
    owner_email = owner.email
    await db_session.commit()

    preview = await claim_legacy_project(
        db_session, project_id, owner_email, "ops-ticket-42", "Customer ownership verified from original invoice", apply=False
    )
    assert preview["dry_run"] is True
    project = await db_session.scalar(__import__("sqlalchemy").select(Project).where(Project.id == project_id))
    assert project.owner_id is None

    applied = await claim_legacy_project(
        db_session, project_id, owner_email, "ops-ticket-42", "Customer ownership verified from original invoice", apply=True
    )
    assert applied["applied"] is True
    await db_session.refresh(project)
    assert project.owner_id == owner.id
    event = await db_session.scalar(
        __import__("sqlalchemy").select(ProjectAuditEvent).where(
            ProjectAuditEvent.project_id == project.id,
            ProjectAuditEvent.action == "ownership.claimed",
        )
    )
    assert event is not None
    assert event.actor_email == "admin:ops-ticket-42"
    assert event.target_user_id == owner.id
    assert "original invoice" in event.details


@pytest.mark.asyncio
async def test_legacy_project_claim_refuses_unverified_or_already_owned_accounts(db_session):
    from app.models import Project, User
    from scripts.claim_legacy_project import claim_legacy_project

    unverified = User(email="unverified-legacy@example.com", password_hash=hash_password("long enough password"), is_email_verified=False)
    existing_owner = User(email="existing-owner@example.com", password_hash=hash_password("long enough password"), is_email_verified=True)
    db_session.add_all([unverified, existing_owner])
    await db_session.flush()
    unowned = Project(title="Unclaimed project")
    owned = Project(title="Already owned project", owner_id=existing_owner.id)
    db_session.add_all([unowned, owned])
    await db_session.flush()

    with pytest.raises(ValueError, match="email-verified"):
        await claim_legacy_project(db_session, unowned.id, unverified.email, "ops-1", "Verification check", apply=True)
    with pytest.raises(ValueError, match="already has an owner"):
        await claim_legacy_project(db_session, owned.id, existing_owner.email, "ops-1", "No overwrite", apply=True)
    await db_session.refresh(unowned)
    assert unowned.owner_id is None



@pytest.mark.asyncio
async def test_failed_action_email_invalidates_undelivered_token(db_session, monkeypatch):
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import select
    import app.main as main
    from app.models import AuthActionToken, User

    user = User(
        email="mail-failure@example.com",
        password_hash=hash_password("a sufficiently long test password"),
        is_email_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    token = AuthActionToken(
        user_id=user.id,
        purpose="password_reset",
        token_hash="b" * 64,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
    )
    db_session.add(token)
    await db_session.commit()
    token_id = token.id

    async def fail_delivery(*args, **kwargs):
        raise RuntimeError("simulated SMTP outage")

    monkeypatch.setattr(main, "send_email", fail_delivery)
    with pytest.raises(RuntimeError, match="SMTP outage"):
        await main._send_action_email(
            db_session, token, user.email, "Password reset", "One-time link"
        )

    stored = await db_session.scalar(
        select(AuthActionToken).where(AuthActionToken.id == token_id)
    )
    assert stored.consumed_at is not None


@pytest.mark.parametrize("environment,secure_expected", [
    ("staging", True),
    ("production", True),
    ("development", False),
    ("test", False),
    ("local", False),
])
def test_auth_cookies_use_secure_flag_outside_local_environments(monkeypatch, environment, secure_expected):
    from starlette.responses import Response
    from app.config import settings
    import app.main as main

    monkeypatch.setattr(settings, "environment", environment)
    response = Response()
    main._set_auth_cookies(response, "access-token", "refresh-token")
    cookies = response.headers.getlist("set-cookie")
    assert len(cookies) == 3
    assert all(("; secure" in cookie.lower()) is secure_expected for cookie in cookies)

    cleared = Response()
    main._clear_auth_cookies(cleared)
    clear_headers = cleared.headers.getlist("set-cookie")
    assert len(clear_headers) == 3
    assert all(("; secure" in cookie.lower()) is secure_expected for cookie in clear_headers)
