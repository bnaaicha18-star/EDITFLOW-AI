"""Bounded ffprobe metadata inspection for source and rendered media."""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass

from app.media_policy import (
    SUPPORTED_AUDIO_CODECS,
    SUPPORTED_VIDEO_CODECS,
    media_input_options,
)


class MediaProbeError(RuntimeError):
    pass


@dataclass(frozen=True)
class MediaInfo:
    duration_seconds: float
    has_video: bool
    has_audio: bool
    width: int | None
    height: int | None
    video_codec: str | None
    audio_codec: str | None
    format_name: str | None = None


async def probe_media(path: str, timeout_seconds: int = 30) -> MediaInfo:
    if timeout_seconds < 1 or timeout_seconds > 300:
        raise ValueError("timeout_seconds must be between 1 and 300")
    try:
        process = await asyncio.create_subprocess_exec(
            "ffprobe", "-v", "error", *media_input_options(),
            "-show_entries",
            "format=duration,format_name:stream=codec_type,codec_name,width,height",
            "-of", "json", path,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise MediaProbeError("ffprobe executable was not found on the worker") from exc
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout_seconds)
    except asyncio.TimeoutError:
        process.kill()
        await process.communicate()
        raise MediaProbeError("ffprobe timed out") from None
    except asyncio.CancelledError:
        process.kill()
        await process.communicate()
        raise
    if process.returncode != 0:
        detail = (stderr or b"").decode("utf-8", errors="replace")[-2000:]
        raise MediaProbeError(f"ffprobe failed: {detail}")
    try:
        payload = json.loads(stdout.decode("utf-8"))
        streams = payload.get("streams", [])
        video = next((s for s in streams if s.get("codec_type") == "video"), None)
        audio = next((s for s in streams if s.get("codec_type") == "audio"), None)
        fmt = payload.get("format", {})
        duration = float(fmt.get("duration", 0))
        if duration <= 0:
            raise ValueError("missing positive duration")
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise MediaProbeError(f"ffprobe returned invalid media metadata: {exc}") from exc
    if video is None:
        raise MediaProbeError("Input asset has no video stream")
    format_name = fmt.get("format_name")
    formats = set(str(format_name or "").split(","))
    if not formats.intersection({"mov", "matroska"}):
        raise MediaProbeError("Unsupported media container; only MP4, MOV, and WebM are accepted")
    video_codec = video.get("codec_name")
    if video_codec not in SUPPORTED_VIDEO_CODECS:
        raise MediaProbeError(f"Unsupported video codec: {video_codec or 'unknown'}")
    audio_codec = audio.get("codec_name") if audio else None
    if audio_codec is not None and audio_codec not in SUPPORTED_AUDIO_CODECS:
        raise MediaProbeError(f"Unsupported audio codec: {audio_codec}")
    return MediaInfo(
        duration_seconds=duration,
        has_video=True,
        has_audio=audio is not None,
        width=int(video["width"]) if video.get("width") else None,
        height=int(video["height"]) if video.get("height") else None,
        video_codec=video_codec,
        audio_codec=audio_codec,
        format_name=format_name,
    )
