from uuid import UUID, uuid4
from datetime import datetime, timedelta, timezone
import asyncio
import hashlib
import os
import secrets
import tempfile
from pathlib import Path
from fastapi import FastAPI, Depends, HTTPException, Request, Response, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse, JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from app.config import settings, validate_production_settings
from app.db import get_db
from app.rendering import create_render_job, get_render_job, request_render_cancellation, RenderJobNotFound
from sqlalchemy import select, or_, delete, update
from sqlalchemy.exc import IntegrityError
from app.models import Asset, Project, RenderJob, TimelineVersion, User, ProjectMember, UserSession, ProjectAuditEvent, AuthActionToken, ProjectInvitation
from app.schemas import (
    ProjectCreate, SaveTimelineRequest, RestoreRequest, CreateRenderRequest,
    QCCriticApprovalRequest, AuthRegisterRequest, AuthLoginRequest, ProjectMemberUpsert, RefreshTokenRequest, TimelineDocument,
    EmailOnlyRequest, ActionTokenRequest, PasswordResetRequest, ProjectInvitationCreate,
)
from app.qc_critic import (
    generate_qc_critic_proposals, approve_qc_intent_proposals,
    QCCriticNotFound, QCCriticNotReady, StaleQCCriticBase,
)
from app.versioning import (
    save_timeline, list_versions, compare_versions, restore_version,
    VersionConflict, ProjectNotFound,
)
from app.storage import create_object_storage, LocalObjectStorage, S3ObjectStorage, StorageError
from app.auth import get_current_user, hash_password, verify_password, create_access_token, generate_refresh_token, hash_refresh_token
from app.rate_limit import enforce_rate_limit
from app.emailer import send_email
from app.media_probe import probe_media, MediaProbeError

app = FastAPI(title=settings.api_title, version="0.1.0")


@app.on_event("startup")
async def validate_runtime_configuration():
    validate_production_settings()


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    unsafe = request.method.upper() not in {"GET", "HEAD", "OPTIONS", "TRACE"}
    has_session_cookie = bool(request.cookies.get("editflow_access") or request.cookies.get("editflow_refresh"))
    public_cookie_independent = request.url.path in {
        "/v1/auth/register", "/v1/auth/request-password-reset",
        "/v1/auth/resend-verification", "/v1/auth/verify-email",
        "/v1/auth/reset-password",
    }
    if unsafe and has_session_cookie and not public_cookie_independent:
        csrf_cookie = request.cookies.get("editflow_csrf", "")
        csrf_header = request.headers.get("x-csrf-token", "")
        if not csrf_cookie or not csrf_header or not secrets.compare_digest(csrf_cookie, csrf_header):
            from starlette.responses import JSONResponse
            return JSONResponse({"detail": "CSRF validation failed"}, status_code=403, headers={"Cache-Control": "no-store"})
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if request.url.path.startswith("/v1/auth/") or request.url.path.startswith("/v1/invitations/"):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
    return response


_allowed_origins = [origin.strip() for origin in settings.cors_origins.split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Accept", "Content-Type", "Authorization", "X-CSRF-Token", "X-Editflow-Cookie-Auth"],
)

@app.get("/health")
async def health():
    return {"status": "ok"}


async def require_owned_project(
    project_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Project:
    project = await db.scalar(select(Project).where(
        Project.id == project_id,
        Project.owner_id == current_user.id,
    ))
    if project is None:
        # Do not reveal whether another user's project exists.
        raise HTTPException(404, "Project not found")
    return project



async def require_project_access(
    project_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Project:
    project = await db.scalar(
        select(Project)
        .outerjoin(ProjectMember, ProjectMember.project_id == Project.id)
        .where(
            Project.id == project_id,
            or_(Project.owner_id == current_user.id, ProjectMember.user_id == current_user.id),
        )
    )
    if project is None:
        raise HTTPException(404, "Project not found")
    return project


async def require_project_editor(
    project: Project = Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Project:
    if project.owner_id == current_user.id:
        return project
    role = await db.scalar(select(ProjectMember.role).where(
        ProjectMember.project_id == project.id,
        ProjectMember.user_id == current_user.id,
    ))
    if role != "editor":
        raise HTTPException(403, "Editor role is required for this operation")
    return project



def _new_refresh_session(user_id: UUID, family_id: UUID | None = None):
    raw_token = generate_refresh_token()
    session = UserSession(
        user_id=user_id,
        family_id=family_id or uuid4(),
        refresh_token_hash=hash_refresh_token(raw_token),
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.auth_refresh_token_days),
    )
    return raw_token, session


def _cookie_auth_requested(request: Request | None) -> bool:
    return settings.environment.strip().lower() in {"production", "prod"} or bool(request and request.headers.get("x-editflow-cookie-auth") == "1")


def _auth_cookie_secure() -> bool:
    # Staging and every deployed environment must use Secure cookies.
    # Plain HTTP is permitted only for explicit local/test environments.
    return settings.environment.strip().lower() not in {"development", "dev", "test", "local"}


def _set_auth_cookies(response: Response, access_token: str, refresh_token: str) -> None:
    secure = _auth_cookie_secure()
    response.set_cookie("editflow_access", access_token, max_age=settings.auth_access_token_seconds,
        httponly=True, secure=secure, samesite="lax", path="/")
    response.set_cookie("editflow_refresh", refresh_token, max_age=settings.auth_refresh_token_days * 86400,
        httponly=True, secure=secure, samesite="lax", path="/")
    response.set_cookie("editflow_csrf", secrets.token_urlsafe(32), max_age=settings.auth_refresh_token_days * 86400,
        httponly=False, secure=secure, samesite="lax", path="/")


def _clear_auth_cookies(response: Response) -> None:
    secure = _auth_cookie_secure()
    for name in ("editflow_access", "editflow_refresh", "editflow_csrf"):
        response.delete_cookie(name, path="/", secure=secure, httponly=name != "editflow_csrf", samesite="lax")


def _new_action_token(user_id: UUID, purpose: str, lifetime: timedelta):
    raw = secrets.token_urlsafe(40)
    row = AuthActionToken(
        user_id=user_id,
        purpose=purpose,
        token_hash=hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        expires_at=datetime.now(timezone.utc) + lifetime,
    )
    return raw, row


def _email_link(path: str, token: str) -> str:
    return f"{settings.email_public_url.rstrip('/')}/auth-action.html?action={path}#token={token}"

async def _send_action_email(db: AsyncSession, token_row: AuthActionToken, recipient: str, subject: str, body: str) -> None:
    try:
        await send_email(recipient, subject, body)
    except Exception:
        # Do not leave a valid but undelivered verification/reset link in the database.
        await db.execute(update(AuthActionToken).where(
            AuthActionToken.id == token_row.id,
            AuthActionToken.consumed_at.is_(None),
        ).values(consumed_at=datetime.now(timezone.utc)))
        await db.commit()
        raise


@app.post("/v1/auth/register", status_code=202)
async def register_account(payload: AuthRegisterRequest, db: AsyncSession = Depends(get_db), request: Request = None):
    if not settings.auth_secret or len(settings.auth_secret.encode("utf-8")) < 32:
        raise HTTPException(503, "Authentication is not configured")
    client_ip = request.client.host if request and request.client else "unknown"
    await enforce_rate_limit(db, [f"register:ip:{client_ip}"], settings.auth_register_limit, settings.auth_register_window_seconds)
    password_hash = hash_password(payload.password)
    existing = await db.scalar(select(User).where(User.email == payload.email))
    if existing is not None:
        # Keep registration responses and password-hash work comparable for existing/new addresses.
        return {"message": "If the address can be registered, a verification email will be sent."}
    user = User(email=payload.email, password_hash=password_hash, is_email_verified=False)
    db.add(user)
    try:
        await db.flush()
        raw_token, token_row = _new_action_token(user.id, "email_verification", timedelta(hours=24))
        db.add(token_row)
        await db.commit()
    except IntegrityError:
        await db.rollback()
        return {"message": "If the address can be registered, a verification email will be sent."}
    await _send_action_email(
        db, token_row, user.email,
        "Verify your EDITFLOW AI email",
        "Verify your email address using this link (valid for 24 hours):\n"
        + _email_link("verify-email", raw_token)
        + "\nIf you did not create this account, you can ignore this message.",
    )
    return {"message": "If the address can be registered, a verification email will be sent."}


@app.post("/v1/auth/verify-email")
async def verify_email(payload: ActionTokenRequest, db: AsyncSession = Depends(get_db)):
    token_hash = hashlib.sha256(payload.token.encode("utf-8")).hexdigest()
    row = await db.scalar(select(AuthActionToken).where(
        AuthActionToken.token_hash == token_hash,
        AuthActionToken.purpose == "email_verification",
    ).with_for_update())
    now = datetime.now(timezone.utc)
    if row is None or row.consumed_at is not None or row.expires_at <= now:
        raise HTTPException(400, "Verification link is invalid or expired")
    user = await db.scalar(select(User).where(User.id == row.user_id, User.is_active.is_(True)))
    if user is None:
        raise HTTPException(400, "Verification link is invalid or expired")
    user.is_email_verified = True
    row.consumed_at = now
    await db.execute(update(AuthActionToken).where(
        AuthActionToken.user_id == user.id,
        AuthActionToken.purpose == "email_verification",
        AuthActionToken.consumed_at.is_(None),
    ).values(consumed_at=now))
    await db.commit()
    return {"verified": True}


@app.post("/v1/auth/resend-verification")
async def resend_verification(payload: EmailOnlyRequest, db: AsyncSession = Depends(get_db), request: Request = None):
    client_ip = request.client.host if request and request.client else "unknown"
    await enforce_rate_limit(db, [f"verify-resend:ip:{client_ip}", f"verify-resend:email:{payload.email}"], 5, 3600)
    user = await db.scalar(select(User).where(User.email == payload.email, User.is_active.is_(True)))
    if user is not None and not user.is_email_verified:
        await db.execute(update(AuthActionToken).where(
            AuthActionToken.user_id == user.id,
            AuthActionToken.purpose == "email_verification",
            AuthActionToken.consumed_at.is_(None),
        ).values(consumed_at=datetime.now(timezone.utc)))
        raw, row = _new_action_token(user.id, "email_verification", timedelta(hours=24))
        db.add(row)
        await db.commit()
        await _send_action_email(db, row, user.email, "Verify your EDITFLOW AI email",
            "Use this link within 24 hours:\n" + _email_link("verify-email", raw))
    return {"message": "If the account needs verification, an email will be sent."}


@app.post("/v1/auth/request-password-reset")
async def request_password_reset(payload: EmailOnlyRequest, db: AsyncSession = Depends(get_db), request: Request = None):
    client_ip = request.client.host if request and request.client else "unknown"
    await enforce_rate_limit(db, [f"password-reset:ip:{client_ip}", f"password-reset:email:{payload.email}"], 5, 3600)
    user = await db.scalar(select(User).where(User.email == payload.email, User.is_active.is_(True)))
    if user is not None and user.is_email_verified:
        await db.execute(update(AuthActionToken).where(
            AuthActionToken.user_id == user.id,
            AuthActionToken.purpose == "password_reset",
            AuthActionToken.consumed_at.is_(None),
        ).values(consumed_at=datetime.now(timezone.utc)))
        raw, row = _new_action_token(user.id, "password_reset", timedelta(minutes=30))
        db.add(row)
        await db.commit()
        await _send_action_email(db, row, user.email, "Reset your EDITFLOW AI password",
            "Use this link within 30 minutes:\n" + _email_link("reset-password", raw)
            + "\nIf you did not request a reset, ignore this message.")
    return {"message": "If the account exists and is verified, a reset email will be sent."}


@app.post("/v1/auth/reset-password")
async def reset_password(payload: PasswordResetRequest, db: AsyncSession = Depends(get_db)):
    token_hash = hashlib.sha256(payload.token.encode("utf-8")).hexdigest()
    row = await db.scalar(select(AuthActionToken).where(
        AuthActionToken.token_hash == token_hash,
        AuthActionToken.purpose == "password_reset",
    ).with_for_update())
    now = datetime.now(timezone.utc)
    if row is None or row.consumed_at is not None or row.expires_at <= now:
        raise HTTPException(400, "Password reset link is invalid or expired")
    user = await db.scalar(select(User).where(User.id == row.user_id, User.is_active.is_(True)))
    if user is None:
        raise HTTPException(400, "Password reset link is invalid or expired")
    user.password_hash = hash_password(payload.new_password)
    row.consumed_at = now
    await db.execute(update(UserSession).where(
        UserSession.user_id == user.id,
        UserSession.revoked_at.is_(None),
    ).values(revoked_at=now))
    await db.execute(update(AuthActionToken).where(
        AuthActionToken.user_id == user.id,
        AuthActionToken.purpose == "password_reset",
        AuthActionToken.consumed_at.is_(None),
    ).values(consumed_at=now))
    await db.commit()
    return {"password_reset": True, "sessions_revoked": True}


@app.post("/v1/auth/login")
async def login_account(payload: AuthLoginRequest, db: AsyncSession = Depends(get_db), request: Request = None):
    client_ip = request.client.host if request and request.client else "unknown"
    await enforce_rate_limit(db, [f"login:ip:{client_ip}", f"login:identity:{client_ip}:{payload.email}"],
        settings.auth_login_limit, settings.auth_login_window_seconds)
    user = await db.scalar(select(User).where(User.email == payload.email))
    if user is None or not user.is_active or not verify_password(payload.password, user.password_hash) or not user.is_email_verified:
        raise HTTPException(401, "Invalid email or password", headers={"WWW-Authenticate": "Bearer"})
    access_token = create_access_token(user.id)
    refresh_token, session = _new_refresh_session(user.id)
    db.add(session)
    await db.commit()
    result = {"user": {"id": str(user.id), "email": user.email}, "token_type": "bearer",
        "expires_in": settings.auth_access_token_seconds}
    if _cookie_auth_requested(request):
        response = JSONResponse(result)
        _set_auth_cookies(response, access_token, refresh_token)
        return response
    result.update({"access_token": access_token, "refresh_token": refresh_token})
    return JSONResponse(result)


@app.post("/v1/auth/refresh")
async def refresh_account(payload: RefreshTokenRequest | None = None, db: AsyncSession = Depends(get_db), request: Request = None):
    raw_refresh = payload.refresh_token if payload else (request.cookies.get("editflow_refresh") if request else None)
    if not raw_refresh:
        raise HTTPException(401, "Refresh token is required")
    token_hash = hash_refresh_token(raw_refresh)
    session = await db.scalar(select(UserSession).where(UserSession.refresh_token_hash == token_hash).with_for_update())
    if session is None:
        raise HTTPException(401, "Invalid refresh token")
    now = datetime.now(timezone.utc)
    if session.revoked_at is not None:
        await db.execute(update(UserSession).where(UserSession.family_id == session.family_id,
            UserSession.revoked_at.is_(None)).values(revoked_at=now))
        await db.commit()
        raise HTTPException(401, "Refresh token reuse detected; sign in again")
    if session.expires_at <= now:
        session.revoked_at = now
        await db.commit()
        raise HTTPException(401, "Refresh token expired; sign in again")
    user = await db.scalar(select(User).where(User.id == session.user_id, User.is_active.is_(True)))
    if user is None:
        session.revoked_at = now
        await db.commit()
        raise HTTPException(401, "User account is unavailable")
    session.revoked_at = now
    access_token = create_access_token(user.id)
    refresh_token, replacement = _new_refresh_session(user.id, session.family_id)
    db.add(replacement)
    await db.commit()
    result = {"user": {"id": str(user.id), "email": user.email}, "token_type": "bearer",
        "expires_in": settings.auth_access_token_seconds}
    if _cookie_auth_requested(request) or (request and request.cookies.get("editflow_refresh")):
        response = JSONResponse(result)
        _set_auth_cookies(response, access_token, refresh_token)
        return response
    result.update({"access_token": access_token, "refresh_token": refresh_token})
    return JSONResponse(result)


@app.post("/v1/auth/logout")
async def logout_account(payload: RefreshTokenRequest | None = None, db: AsyncSession = Depends(get_db), request: Request = None):
    raw_refresh = payload.refresh_token if payload else (request.cookies.get("editflow_refresh") if request else None)
    if raw_refresh:
        session = await db.scalar(select(UserSession).where(
            UserSession.refresh_token_hash == hash_refresh_token(raw_refresh)).with_for_update())
        if session is not None and session.revoked_at is None:
            now = datetime.now(timezone.utc)
            await db.execute(update(UserSession).where(UserSession.family_id == session.family_id,
                UserSession.revoked_at.is_(None)).values(revoked_at=now))
            await db.commit()
    response = JSONResponse({"revoked": True})
    _clear_auth_cookies(response)
    return response


@app.get("/v1/auth/me")
async def get_authenticated_account(current_user: User = Depends(get_current_user)):
    return {"id": str(current_user.id), "email": current_user.email, "is_active": current_user.is_active, "is_email_verified": current_user.is_email_verified}




MAX_SOURCE_VIDEO_BYTES = 512 * 1024 * 1024
ALLOWED_VIDEO_TYPES = {
    "video/mp4": {".mp4", ".m4v"},
    "video/quicktime": {".mov"},
    "video/webm": {".webm"},
}


@app.get("/v1/projects")
async def list_projects(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    rows = (await db.execute(
        select(Project).where(Project.owner_id == current_user.id).order_by(Project.created_at.desc())
    )).scalars().all()
    return [{"id": str(row.id), "title": row.title, "current_version_id": str(row.current_version_id) if row.current_version_id else None,
             "created_at": row.created_at} for row in rows]


@app.get("/v1/projects/{project_id}/assets")
async def list_project_assets(project_id: UUID, db: AsyncSession = Depends(get_db),
                              _project: Project = Depends(require_project_access)):
    rows = (await db.execute(
        select(Asset).where(Asset.project_id == project_id).order_by(Asset.created_at.desc())
    )).scalars().all()
    return [{
        "id": str(row.id), "original_filename": row.original_filename,
        "mime_type": row.mime_type, "size_bytes": row.size_bytes,
        "duration_seconds": row.duration_seconds, "width": row.width, "height": row.height,
        "checksum_sha256": row.checksum_sha256, "created_at": row.created_at,
    } for row in rows]


@app.post("/v1/projects/{project_id}/assets", status_code=201)
async def upload_project_video(project_id: UUID, file: UploadFile = File(...),
                               db: AsyncSession = Depends(get_db),
                               project: Project = Depends(require_project_editor)):
    """Stream, validate and checksum a source video before linking it to a timeline."""
    content_type = (file.content_type or "").lower().split(";", 1)[0].strip()
    extension = Path(file.filename or "").suffix.lower()
    if content_type not in ALLOWED_VIDEO_TYPES or extension not in ALLOWED_VIDEO_TYPES[content_type]:
        raise HTTPException(415, "Supported source videos are MP4, MOV and WebM with matching file extensions")
    safe_name = Path(file.filename or "source-video").name[:255]
    suffix = extension
    temp_path = None
    asset_id = uuid4()
    object_key = f"uploads/{project_id}/{asset_id}{suffix}"
    digest = hashlib.sha256()
    total = 0
    signature = b""
    try:
        with tempfile.NamedTemporaryFile(prefix="editflow-upload-", suffix=suffix, delete=False) as temp:
            temp_path = temp.name
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_SOURCE_VIDEO_BYTES:
                    raise HTTPException(413, "Video exceeds the 512 MiB upload limit")
                if len(signature) < 16:
                    signature += chunk[:16 - len(signature)]
                digest.update(chunk)
                temp.write(chunk)
        if total <= 0:
            raise HTTPException(400, "Uploaded video is empty")
        is_mp4 = len(signature) >= 12 and signature[4:8] == b"ftyp"
        is_webm = signature.startswith(b"\x1aE\xdf\xa3")
        if (content_type in {"video/mp4", "video/quicktime"} and not is_mp4) or (content_type == "video/webm" and not is_webm):
            raise HTTPException(415, "The uploaded file signature does not match its declared video type")
        try:
            info = await probe_media(temp_path, timeout_seconds=45)
        except MediaProbeError as exc:
            raise HTTPException(422, f"Video could not be decoded or probed: {str(exc)[:300]}") from exc
        if info.duration_seconds > 4 * 60 * 60:
            raise HTTPException(413, "Source videos longer than four hours are not supported")
        storage = create_object_storage(settings)
        await asyncio.to_thread(storage.put_file, temp_path, object_key)
        asset = Asset(
            id=asset_id, project_id=project_id, object_key=object_key,
            checksum_sha256=digest.hexdigest(), original_filename=safe_name,
            mime_type=content_type, size_bytes=total, duration_seconds=info.duration_seconds,
            width=info.width, height=info.height,
        )
        db.add(asset)
        latest = None
        if project.current_version_id:
            latest = await db.scalar(select(TimelineVersion).where(
                TimelineVersion.id == project.current_version_id,
                TimelineVersion.project_id == project_id,
            ))
        clips = list(latest.timeline_json.get("clips", [])) if latest else []
        clips.append({
            "id": str(uuid4()), "asset_id": str(asset_id), "track_id": "video-1",
            "timeline_start": max((float(clip.get("timeline_start", 0)) +
                float(clip.get("source_out", 0)) - float(clip.get("source_in", 0)) for clip in clips), default=0),
            "source_in": 0, "source_out": info.duration_seconds,
            "transform": {}, "audio_gain_db": 0,
        })
        timeline_data = {
            "schema_version": "0.1", "project_id": str(project_id),
            "version": 0, "sequence": (latest.timeline_json.get("sequence", {}) if latest else {
                "width": 1080, "height": 1920, "fps": 30,
            }),
            "clips": clips, "editorial_notes": (latest.timeline_json.get("editorial_notes", []) if latest else []),
            "qc_intent": (latest.timeline_json.get("qc_intent", []) if latest else []),
        }
        timeline = TimelineDocument.model_validate(timeline_data)
        version, created = await save_timeline(
            db, project_id, timeline, latest.version if latest else 0,
            message=f"Added source video: {safe_name}",
            idempotency_key=f"upload-{asset_id}",
        )
        await db.commit()
        return {
            "asset": {
                "id": str(asset.id), "original_filename": asset.original_filename,
                "mime_type": asset.mime_type, "size_bytes": asset.size_bytes,
                "duration_seconds": asset.duration_seconds, "width": asset.width, "height": asset.height,
                "checksum_sha256": asset.checksum_sha256,
            },
            "timeline": {"version": version.version, "version_id": str(version.id), "created": created},
        }
    except HTTPException:
        raise
    except StorageError as exc:
        raise HTTPException(502, "Source video could not be stored in object storage") from exc
    finally:
        await file.close()
        if temp_path:
            Path(temp_path).unlink(missing_ok=True)


@app.post("/v1/projects", status_code=201)
async def create_project(payload: ProjectCreate, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    project = Project(title=payload.title.strip(), owner_id=current_user.id)
    db.add(project)
    await db.commit()
    await db.refresh(project)
    return {"id": str(project.id), "title": project.title, "current_version_id": None}


@app.get("/v1/projects/{project_id}/members")
async def list_project_members(
    project_id: UUID,
    db: AsyncSession = Depends(get_db),
    _owned_project: Project = Depends(require_owned_project),
):
    owner = await db.scalar(select(User).where(User.id == _owned_project.owner_id))
    members = (await db.execute(
        select(ProjectMember, User)
        .join(User, User.id == ProjectMember.user_id)
        .where(ProjectMember.project_id == project_id)
        .order_by(User.email)
    )).all()
    result = []
    if owner is not None:
        result.append({"user_id": str(owner.id), "email": owner.email, "role": "owner"})
    result.extend({
        "user_id": str(member.user_id),
        "email": user.email,
        "role": member.role,
        "created_at": member.created_at,
    } for member, user in members)
    return result


@app.get("/v1/projects/{project_id}/audit-log")
async def list_project_audit_events(
    project_id: UUID,
    db: AsyncSession = Depends(get_db),
    _owned_project: Project = Depends(require_owned_project),
):
    events = (await db.execute(
        select(ProjectAuditEvent)
        .where(ProjectAuditEvent.project_id == project_id)
        .order_by(ProjectAuditEvent.created_at.desc(), ProjectAuditEvent.id.desc())
    )).scalars().all()
    return [{
        "id": str(event.id),
        "actor_user_id": str(event.actor_user_id) if event.actor_user_id else None,
        "actor_email": event.actor_email,
        "target_user_id": str(event.target_user_id) if event.target_user_id else None,
        "target_email": event.target_email,
        "action": event.action,
        "previous_role": event.previous_role,
        "new_role": event.new_role,
        "created_at": event.created_at,
    } for event in events]


@app.post("/v1/projects/{project_id}/invitations", status_code=202)
async def create_project_invitation(
    project_id: UUID,
    payload: ProjectInvitationCreate,
    db: AsyncSession = Depends(get_db),
    request: Request = None,
    _owned_project: Project = Depends(require_owned_project),
):
    client_ip = request.client.host if request and request.client else "unknown"
    await enforce_rate_limit(
        db,
        [f"invite:project:{project_id}", f"invite:recipient:{payload.email}", f"invite:ip:{client_ip}"],
        10,
        3600,
    )
    if payload.email == (await db.scalar(select(User.email).where(User.id == _owned_project.owner_id))):
        raise HTTPException(409, "The project owner already has full access")
    now = datetime.now(timezone.utc)
    # A new invitation replaces older unaccepted invitations for this project/email.
    await db.execute(update(ProjectInvitation).where(
        ProjectInvitation.project_id == project_id,
        ProjectInvitation.invited_email == payload.email,
        ProjectInvitation.accepted_at.is_(None),
        ProjectInvitation.revoked_at.is_(None),
        ProjectInvitation.expires_at > now,
    ).values(revoked_at=now))
    raw = secrets.token_urlsafe(40)
    invitation = ProjectInvitation(
        project_id=project_id,
        inviter_user_id=_owned_project.owner_id,
        invited_email=payload.email,
        role=payload.role,
        token_hash=hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        expires_at=now + timedelta(days=7),
    )
    db.add(invitation)
    await db.commit()
    try:
        await send_email(
            payload.email,
            "You are invited to collaborate in EDITFLOW AI",
            f"You were invited as {payload.role}. Sign in or create an account with this email, verify it, then accept the invitation using this link (valid for 7 days):\n"
            + _email_link("accept-invitation", raw),
        )
    except Exception:
        invitation.revoked_at = datetime.now(timezone.utc)
        await db.commit()
        raise
    return {"message": "Invitation sent", "expires_in_seconds": 604800}


@app.post("/v1/invitations/accept")
async def accept_project_invitation(
    payload: ActionTokenRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not current_user.is_email_verified:
        raise HTTPException(403, "Verify your email before accepting invitations")
    digest = hashlib.sha256(payload.token.encode("utf-8")).hexdigest()
    invitation = await db.scalar(select(ProjectInvitation).where(
        ProjectInvitation.token_hash == digest,
    ).with_for_update())
    now = datetime.now(timezone.utc)
    if (invitation is None or invitation.accepted_at is not None
        or invitation.revoked_at is not None or invitation.expires_at <= now):
        raise HTTPException(400, "Invitation is invalid or expired")
    if invitation.invited_email != current_user.email:
        raise HTTPException(403, "This invitation belongs to a different email address")
    project = await db.scalar(select(Project).where(Project.id == invitation.project_id))
    if project is None:
        raise HTTPException(404, "Project not found")
    if project.owner_id == current_user.id:
        raise HTTPException(409, "Project owner already has full access")
    member = await db.scalar(select(ProjectMember).where(
        ProjectMember.project_id == project.id,
        ProjectMember.user_id == current_user.id,
    ))
    previous_role = member.role if member is not None else None
    if member is None:
        member = ProjectMember(project_id=project.id, user_id=current_user.id, role=invitation.role)
        db.add(member)
        action = "member.added"
    elif member.role != invitation.role:
        member.role = invitation.role
        action = "member.role_changed"
    else:
        action = None
    if action:
        owner = await db.scalar(select(User).where(User.id == project.owner_id))
        db.add(ProjectAuditEvent(
            project_id=project.id,
            actor_user_id=current_user.id,
            actor_email=current_user.email,
            target_user_id=current_user.id,
            target_email=current_user.email,
            action=action,
            previous_role=previous_role,
            new_role=invitation.role,
        ))
    invitation.accepted_at = now
    await db.commit()
    return {"accepted": True, "project_id": str(project.id), "role": invitation.role}


@app.post("/v1/projects/{project_id}/members", status_code=200)
async def upsert_project_member(
    project_id: UUID,
    payload: ProjectMemberUpsert,
    db: AsyncSession = Depends(get_db),
    _owned_project: Project = Depends(require_owned_project),
):
    owner = await db.scalar(select(User).where(User.id == _owned_project.owner_id))
    user = await db.scalar(select(User).where(User.email == payload.email, User.is_active.is_(True)))
    if user is None:
        raise HTTPException(404, "An active account with this email was not found")
    if user.id == _owned_project.owner_id:
        raise HTTPException(409, "The project owner already has full access")
    member = await db.scalar(select(ProjectMember).where(
        ProjectMember.project_id == project_id,
        ProjectMember.user_id == user.id,
    ))
    previous_role = member.role if member is not None else None
    if member is None:
        member = ProjectMember(project_id=project_id, user_id=user.id, role=payload.role)
        db.add(member)
        action = "member.added"
    elif member.role != payload.role:
        member.role = payload.role
        action = "member.role_changed"
    else:
        action = None
    if action is not None:
        db.add(ProjectAuditEvent(
            project_id=project_id,
            actor_user_id=_owned_project.owner_id,
            actor_email=owner.email if owner else "unknown",
            target_user_id=user.id,
            target_email=user.email,
            action=action,
            previous_role=previous_role,
            new_role=payload.role,
        ))
    await db.commit()
    await db.refresh(member)
    return {"user_id": str(user.id), "email": user.email, "role": member.role}


@app.delete("/v1/projects/{project_id}/members/{member_user_id}", status_code=204)
async def remove_project_member(
    project_id: UUID,
    member_user_id: UUID,
    db: AsyncSession = Depends(get_db),
    _owned_project: Project = Depends(require_owned_project),
):
    owner = await db.scalar(select(User).where(User.id == _owned_project.owner_id))
    member = await db.scalar(select(ProjectMember).where(
        ProjectMember.project_id == project_id,
        ProjectMember.user_id == member_user_id,
    ))
    if member is None:
        raise HTTPException(404, "Project member not found")
    target = await db.scalar(select(User).where(User.id == member_user_id))
    if target is None:
        raise HTTPException(404, "Project member not found")
    db.add(ProjectAuditEvent(
        project_id=project_id,
        actor_user_id=_owned_project.owner_id,
        actor_email=owner.email if owner else "unknown",
        target_user_id=target.id,
        target_email=target.email,
        action="member.removed",
        previous_role=member.role,
        new_role=None,
    ))
    await db.delete(member)
    await db.commit()
    return None

@app.post("/v1/projects/{project_id}/timeline")
async def save_project_timeline(project_id: UUID, payload: SaveTimelineRequest, db: AsyncSession = Depends(get_db), _owned_project: Project = Depends(require_project_editor)):
    try:
        async with db.begin():
            row, created = await save_timeline(
                db, project_id, payload.timeline, payload.expected_version,
                payload.message,
                idempotency_key=payload.idempotency_key,
            )
        return {"created": created, "version": row.version, "version_id": str(row.id), "content_hash": row.content_hash}
    except ProjectNotFound:
        raise HTTPException(404, "Project not found")
    except VersionConflict as exc:
        raise HTTPException(409, str(exc))
    except ValueError as exc:
        raise HTTPException(422, str(exc))

@app.get("/v1/projects/{project_id}/versions")
async def get_versions(project_id: UUID, db: AsyncSession = Depends(get_db), _owned_project: Project = Depends(require_project_access)):
    rows = await list_versions(db, project_id)
    return [{
        "id": str(r.id), "version": r.version, "parent_version_id": str(r.parent_version_id) if r.parent_version_id else None,
        "restored_from_version_id": str(r.restored_from_version_id) if r.restored_from_version_id else None,
        "message": r.message, "content_hash": r.content_hash, "created_at": r.created_at,
    } for r in rows]

@app.get("/v1/projects/{project_id}/versions/compare")
async def compare_project_versions(project_id: UUID, from_version: int, to_version: int, db: AsyncSession = Depends(get_db), _owned_project: Project = Depends(require_project_access)):
    try:
        return await compare_versions(db, project_id, from_version, to_version)
    except LookupError as exc:
        raise HTTPException(404, str(exc))

@app.post("/v1/projects/{project_id}/versions/{source_version}/restore")
async def restore_project_version(project_id: UUID, source_version: int, payload: RestoreRequest, db: AsyncSession = Depends(get_db), _owned_project: Project = Depends(require_project_editor)):
    try:
        async with db.begin():
            row, created = await restore_version(
                db, project_id, source_version, payload.expected_version, payload.message
            )
        return {"created": created, "version": row.version, "version_id": str(row.id),
                "restored_from_version_id": str(row.restored_from_version_id) if row.restored_from_version_id else None}
    except LookupError as exc:
        raise HTTPException(404, str(exc))
    except VersionConflict as exc:
        raise HTTPException(409, str(exc))
    except ValueError as exc:
        raise HTTPException(422, str(exc))


@app.post("/v1/projects/{project_id}/renders", status_code=202)
async def create_project_render(project_id: UUID, payload: CreateRenderRequest, db: AsyncSession = Depends(get_db), _owned_project: Project = Depends(require_project_editor)):
    try:
        async with db.begin():
            job, created = await create_render_job(
                db, project_id, payload.timeline_version,
                payload.render_profile, payload.request_key,
            )
        return {
            "created": created,
            "job_id": str(job.id),
            "status": job.status,
            "timeline_version_id": str(job.timeline_version_id),
            "timeline_hash": job.timeline_hash,
            "created_at": job.created_at,
        }
    except ProjectNotFound:
        raise HTTPException(404, "Project not found")
    except LookupError as exc:
        raise HTTPException(404, str(exc))
    except VersionConflict as exc:
        raise HTTPException(409, str(exc))
    except ValueError as exc:
        raise HTTPException(422, str(exc))

@app.get("/v1/projects/{project_id}/renders/{job_id}")
async def get_project_render(project_id: UUID, job_id: UUID, db: AsyncSession = Depends(get_db), _owned_project: Project = Depends(require_project_access)):
    try:
        job = await get_render_job(db, project_id, job_id)
        return {
            "job_id": str(job.id),
            "status": job.status,
            "timeline_version_id": str(job.timeline_version_id),
            "timeline_hash": job.timeline_hash,
            "render_profile": job.render_profile,
            "output_object_key": job.output_object_key,
            "error_message": job.error_message,
            "quality_report": job.quality_report,
            "attempts": job.attempts,
            "max_attempts": job.max_attempts,
            "progress_percent": job.progress_percent,
            "cancel_requested": job.cancel_requested,
            "created_at": job.created_at,
            "started_at": job.started_at,
            "completed_at": job.completed_at,
        }
    except RenderJobNotFound:
        raise HTTPException(404, "Render job not found")



@app.get("/v1/projects/{project_id}/renders/{job_id}/media")
async def stream_project_render_media(project_id: UUID, job_id: UUID, db: AsyncSession = Depends(get_db), _owned_project: Project = Depends(require_project_access)):
    """Serve the immutable rendered MP4 with browser seeking / HTTP range support."""
    job = await db.scalar(select(RenderJob).where(
        RenderJob.id == job_id, RenderJob.project_id == project_id
    ))
    if job is None:
        raise HTTPException(404, "Render job not found")
    if job.status != "succeeded" or not job.output_object_key:
        raise HTTPException(409, "Rendered media is not available until the job succeeds")
    try:
        storage = create_object_storage(settings)
        if isinstance(storage, S3ObjectStorage):
            return RedirectResponse(
                url=storage.create_download_url(job.output_object_key, expires_seconds=900),
                status_code=307,
                headers={"Cache-Control": "private, no-store"},
            )
        if isinstance(storage, LocalObjectStorage):
            path = storage.resolve_path(job.output_object_key)
            if not path.is_file() or path.stat().st_size <= 0:
                raise HTTPException(404, "Rendered media file is missing")
            return FileResponse(
                path=path,
                media_type="video/mp4",
                headers={"Cache-Control": "private, no-store", "Accept-Ranges": "bytes"},
            )
        raise HTTPException(500, "Unsupported object storage backend")
    except StorageError as exc:
        raise HTTPException(404, "Rendered media could not be resolved") from exc

@app.post("/v1/projects/{project_id}/renders/{job_id}/cancel")
async def cancel_project_render(project_id: UUID, job_id: UUID, db: AsyncSession = Depends(get_db), _owned_project: Project = Depends(require_project_editor)):
    try:
        async with db.begin():
            job = await request_render_cancellation(db, project_id, job_id)
        return {
            "job_id": str(job.id),
            "status": job.status,
            "cancel_requested": job.cancel_requested,
        }
    except RenderJobNotFound:
        raise HTTPException(404, "Render job not found")


@app.get("/v1/projects/{project_id}/renders/{job_id}/qc-critic")
async def get_qc_critic_suggestions(project_id: UUID, job_id: UUID, db: AsyncSession = Depends(get_db), _owned_project: Project = Depends(require_project_access)):
    job = await db.scalar(select(RenderJob).where(
        RenderJob.id == job_id, RenderJob.project_id == project_id
    ))
    if job is None:
        raise HTTPException(404, "Render job not found")
    if job.status != "succeeded":
        raise HTTPException(409, "QC Critic suggestions are available only after a successful render")
    return {
        "job_id": str(job.id),
        "timeline_version_id": str(job.timeline_version_id),
        **generate_qc_critic_proposals(job.quality_report, job.timeline_snapshot),
    }


@app.get("/v1/projects/{project_id}/renders/{job_id}/story-continuity")
async def get_story_continuity_graph(project_id: UUID, job_id: UUID, db: AsyncSession = Depends(get_db), _owned_project: Project = Depends(require_project_access)):
    job = await db.scalar(select(RenderJob).where(
        RenderJob.id == job_id, RenderJob.project_id == project_id
    ))
    if job is None:
        raise HTTPException(404, "Render job not found")
    if job.status != "succeeded":
        raise HTTPException(409, "Story Continuity Graph is available only after a successful render")
    report = job.quality_report if isinstance(job.quality_report, dict) else {}
    graph = report.get("story_continuity_graph")
    if not isinstance(graph, dict):
        raise HTTPException(404, "Story Continuity Graph is not available for this render")
    return {
        "job_id": str(job.id),
        "timeline_version_id": str(job.timeline_version_id),
        "timeline_hash": job.timeline_hash,
        "media_available": bool(job.output_object_key),
        "media_url": f"/v1/projects/{project_id}/renders/{job_id}/media" if job.output_object_key else None,
        "graph": graph,
    }


@app.post("/v1/projects/{project_id}/renders/{job_id}/qc-critic/approve")
async def approve_qc_critic_suggestions(
    project_id: UUID, job_id: UUID, payload: QCCriticApprovalRequest,
    db: AsyncSession = Depends(get_db),
    _owned_project: Project = Depends(require_owned_project),
):
    try:
        async with db.begin():
            row, created, approved_count = await approve_qc_intent_proposals(
                db, project_id, job_id, payload.proposal_ids, payload.expected_version
            )
        return {
            "created": created,
            "approved_count": approved_count,
            "version": row.version,
            "version_id": str(row.id),
            "content_hash": row.content_hash,
            "message": "Approved intent annotations were saved as a new immutable timeline version."
            if created else "The approved annotations already match the current timeline.",
        }
    except QCCriticNotFound:
        raise HTTPException(404, "Render job not found")
    except QCCriticNotReady:
        raise HTTPException(409, "QC Critic approval requires a succeeded render with a QC report")
    except StaleQCCriticBase as exc:
        raise HTTPException(409, str(exc))
    except VersionConflict as exc:
        raise HTTPException(409, str(exc))
    except ValueError as exc:
        raise HTTPException(422, str(exc))
