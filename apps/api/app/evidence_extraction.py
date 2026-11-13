"""Timestamped, worker-side media evidence extraction.

FFmpeg extracts representative frames and a normalized audio artifact. Optional
Whisper ASR returns timestamped transcript segments. Visual semantics are never
fabricated: keyframes remain explicit review artifacts until a vision provider
is configured.
"""
from __future__ import annotations

import asyncio
import base64
import json
import re
import sys
from pathlib import Path
from typing import Any

import httpx

from app.scene_detection import SceneDetectionError, detect_scene_changes


class EvidenceExtractionError(RuntimeError):
    pass


async def _run(argv: list[str], timeout_seconds: int) -> tuple[bytes, bytes]:
    try:
        process = await asyncio.create_subprocess_exec(
            *argv, stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise EvidenceExtractionError(f"Required executable not found: {argv[0]}") from exc
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout_seconds)
    except asyncio.TimeoutError:
        process.kill()
        await process.communicate()
        raise EvidenceExtractionError(f"Evidence extraction timed out after {timeout_seconds}s") from None
    except asyncio.CancelledError:
        process.kill()
        await process.communicate()
        raise
    if process.returncode != 0:
        detail = (stderr or b"").decode("utf-8", errors="replace")[-1800:]
        raise EvidenceExtractionError(f"{argv[0]} failed ({process.returncode}): {detail}")
    return stdout or b"", stderr or b""


def _select_timestamps(values: list[float], duration: float, max_frames: int) -> list[float]:
    clean = sorted({
        round(max(0.0, min(float(value), max(0.0, duration - 0.04))), 3)
        for value in values if 0 <= float(value) < duration
    })
    if not clean:
        clean = [0.0]
    if len(clean) > max_frames:
        indexes = [round(i * (len(clean) - 1) / (max_frames - 1)) for i in range(max_frames)]
        clean = [clean[index] for index in sorted(set(indexes))]
    return clean


async def _scene_change_timestamps(video_path: str, threshold: float, timeout_seconds: int) -> list[float]:
    """Prefer PySceneDetect in a killable subprocess; retain FFmpeg as fallback."""
    script = (
        "import json, sys; "
        "from app.scene_detection import detect_scene_changes; "
        "print(json.dumps(detect_scene_changes(sys.argv[1], float(sys.argv[2]))))"
    )
    process = None
    try:
        process = await asyncio.create_subprocess_exec(
            sys.executable, "-c", script, video_path, str(threshold),
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            process.communicate(), timeout=max(1, timeout_seconds),
        )
        if process.returncode != 0:
            detail = stderr.decode("utf-8", errors="replace")[-1200:]
            raise SceneDetectionError(f"PySceneDetect subprocess failed: {detail}")
        values = json.loads(stdout.decode("utf-8"))
        if not isinstance(values, list):
            raise SceneDetectionError("PySceneDetect returned an invalid result")
        return [float(value) for value in values]
    except asyncio.CancelledError:
        if process is not None and process.returncode is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            await process.communicate()
        raise
    except asyncio.TimeoutError:
        if process is not None and process.returncode is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            await process.communicate()
        return await _ffmpeg_scene_change_timestamps(video_path, threshold, timeout_seconds)
    except (OSError, ValueError, json.JSONDecodeError, SceneDetectionError):
        if process is not None and process.returncode is None:
            process.kill()
            await process.communicate()
        return await _ffmpeg_scene_change_timestamps(video_path, threshold, timeout_seconds)


async def _ffmpeg_scene_change_timestamps(
    video_path: str, threshold: float, timeout_seconds: int,
) -> list[float]:
    """Fallback detector, bounded by the same caller-provided timeout."""
    _, stderr = await _run([
        "ffmpeg", "-hide_banner", "-nostdin", "-v", "info", "-i", video_path,
        "-vf", f"select='gt(scene,{threshold})',showinfo", "-an", "-f", "null", "-",
    ], timeout_seconds)
    return [float(value) for value in re.findall(
        r"pts_time:([0-9]+(?:\.[0-9]+)?)",
        stderr.decode("utf-8", errors="replace"),
    )]

async def _perceptual_hash(image_path: str | Path) -> str | None:
    """Compute a compact 64-bit difference hash using FFmpeg only."""
    try:
        raw, _ = await _run([
            "ffmpeg", "-hide_banner", "-loglevel", "error", "-nostdin",
            "-i", str(image_path), "-vf", "scale=9:8:flags=area,format=gray",
            "-frames:v", "1", "-f", "rawvideo", "-",
        ], 30)
    except EvidenceExtractionError:
        return None
    if len(raw) < 72:
        return None
    bits = 0
    bit_index = 0
    for row in range(8):
        for column in range(8):
            left = raw[row * 9 + column]
            right = raw[row * 9 + column + 1]
            if left > right:
                bits |= 1 << bit_index
            bit_index += 1
    return f"{bits:016x}"


async def extract_representative_keyframes(
    video_path: str, output_dir: str | Path, *, duration_seconds: float,
    sample_interval_seconds: float = 5.0, scene_threshold: float = 0.30,
    max_frames: int = 48, timeout_seconds: int = 900,
) -> list[dict[str, Any]]:
    if duration_seconds <= 0 or sample_interval_seconds <= 0:
        raise ValueError("duration and sample interval must be positive")
    if not 2 <= max_frames <= 200:
        raise ValueError("max_frames must be between 2 and 200")
    if not 0.05 <= scene_threshold <= 0.95:
        raise ValueError("scene_threshold must be between 0.05 and 0.95")
    target = Path(output_dir)
    target.mkdir(parents=True, exist_ok=True)

    try:
        scene_times = await _scene_change_timestamps(video_path, scene_threshold, timeout_seconds)
    except EvidenceExtractionError:
        scene_times = []
    interval_times = []
    current = 0.0
    while current < duration_seconds:
        interval_times.append(current)
        current += sample_interval_seconds
    timestamps = _select_timestamps([*interval_times, *scene_times], duration_seconds, max_frames)

    frames: list[dict[str, Any]] = []
    for index, timestamp in enumerate(timestamps):
        filename = f"frame_{index + 1:03d}.jpg"
        output = target / filename
        await _run([
            "ffmpeg", "-hide_banner", "-loglevel", "error", "-nostdin",
            "-ss", f"{timestamp:.3f}", "-i", video_path, "-frames:v", "1",
            "-vf", "scale='min(640,iw)':-2", "-q:v", "4", "-y", str(output),
        ], min(timeout_seconds, 120))
        if not output.is_file() or output.stat().st_size <= 0:
            raise EvidenceExtractionError(f"No keyframe generated at {timestamp:.3f}s")
        next_time = timestamps[index + 1] if index + 1 < len(timestamps) else duration_seconds
        frames.append({
            "timestamp_seconds": timestamp,
            "perceptual_hash": await _perceptual_hash(output),
            "end_seconds": round(max(timestamp, next_time), 3),
            "filename": filename,
            "sample_type": "scene_change" if any(abs(timestamp - item) < 0.002 for item in scene_times)
                           else "interval_sample",
            "size_bytes": output.stat().st_size,
        })
    return frames


async def extract_audio_track(video_path: str, output_path: str | Path, timeout_seconds: int = 900) -> Path:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    await _run([
        "ffmpeg", "-hide_banner", "-loglevel", "error", "-nostdin", "-i", video_path,
        "-vn", "-ac", "1", "-ar", "16000", "-c:a", "libmp3lame", "-b:a", "48k",
        "-y", str(output),
    ], timeout_seconds)
    if not output.is_file() or output.stat().st_size <= 0:
        raise EvidenceExtractionError("Audio extraction produced an empty file")
    return output


async def transcribe_with_whisper(
    audio_path: str | Path, *, api_key: str | None,
    endpoint: str = "https://api.openai.com/v1/audio/transcriptions",
    model: str = "whisper-1", timeout_seconds: int = 900,
) -> dict[str, Any]:
    if not api_key:
        return {"status": "not_configured", "provider": None, "segments": []}
    path = Path(audio_path)
    if path.stat().st_size > 24 * 1024 * 1024:
        return {"status": "audio_too_large", "provider": "openai_whisper", "segments": [],
                "message": "Audio exceeds the 24 MB upload safety limit; chunking is required."}
    try:
        async with httpx.AsyncClient(timeout=timeout_seconds) as client:
            with path.open("rb") as handle:
                response = await client.post(
                    endpoint, headers={"Authorization": f"Bearer {api_key}"},
                    data={"model": model, "response_format": "verbose_json",
                          "timestamp_granularities[]": "segment"},
                    files={"file": (path.name, handle, "audio/mpeg")},
                )
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:
        return {"status": "failed", "provider": "openai_whisper", "segments": [],
                "message": str(exc)[:500]}
    segments = []
    for item in payload.get("segments", []):
        try:
            start, end = float(item["start"]), float(item["end"])
        except (KeyError, TypeError, ValueError):
            continue
        text = item.get("text")
        if end > start and isinstance(text, str) and text.strip():
            segments.append({
                "start_seconds": round(start, 3), "end_seconds": round(end, 3),
                "text": text.strip()[:1000], "source": "openai_whisper",
            })
    return {
        "status": "completed", "provider": "openai_whisper",
        "language": payload.get("language"), "text": str(payload.get("text") or "")[:20000],
        "segments": segments,
    }


async def analyze_keyframes_with_vision(
    frames: list[dict[str, Any]], frames_dir: str | Path, *,
    api_key: str | None,
    endpoint: str = "https://api.openai.com/v1/chat/completions",
    model: str = "gpt-4o-mini",
    timeout_seconds: int = 900,
    batch_size: int = 6,
) -> dict[str, Any]:
    """Generate timestamped, image-grounded descriptions when a vision key is configured."""
    if not api_key:
        return {"status": "not_configured", "provider": None, "model": None, "observations": []}
    if not 1 <= batch_size <= 8:
        raise ValueError("vision batch_size must be between 1 and 8")
    root = Path(frames_dir)
    observations: list[dict[str, Any]] = []
    try:
        async with httpx.AsyncClient(timeout=timeout_seconds) as client:
            for offset in range(0, len(frames), batch_size):
                batch = frames[offset:offset + batch_size]
                content_parts: list[dict[str, Any]] = [{
                    "type": "text",
                    "text": (
                        "Describe only directly visible content in each numbered frame. "
                        "Do not infer intent, hidden events, identities, or causes. "
                        "Return JSON only with this shape: frames -> [{frame_id, description}]. "
                        "Keep each description factual and under 45 words."
                    ),
                }]
                for index, frame in enumerate(batch):
                    frame_path = root / frame["filename"]
                    encoded = base64.b64encode(frame_path.read_bytes()).decode("ascii")
                    content_parts.append({
                        "type": "text",
                        "text": f"frame_id={index} timestamp_seconds={frame['timestamp_seconds']}",
                    })
                    content_parts.append({
                        "type": "image_url",
                        "image_url": {"url": f"data:image/jpeg;base64,{encoded}", "detail": "low"},
                    })
                response = await client.post(
                    endpoint,
                    headers={"Authorization": f"Bearer {api_key}"},
                    json={
                        "model": model,
                        "temperature": 0,
                        "response_format": {"type": "json_object"},
                        "messages": [{"role": "user", "content": content_parts}],
                    },
                )
                response.raise_for_status()
                payload = response.json()
                raw = payload["choices"][0]["message"]["content"]
                parsed = json.loads(raw)
                by_id = {
                    str(item.get("frame_id")): item.get("description")
                    for item in parsed.get("frames", []) if isinstance(item, dict)
                }
                for index, frame in enumerate(batch):
                    description = by_id.get(str(index))
                    if isinstance(description, str) and description.strip():
                        observations.append({
                            "start_seconds": float(frame["timestamp_seconds"]),
                            "end_seconds": float(frame["end_seconds"]),
                            "description": description.strip()[:500],
                            "source": "openai_vision",
                            "model": model,
                        })
    except Exception as exc:
        return {
            "status": "failed", "provider": "openai_compatible_vision",
            "model": model, "observations": observations, "message": str(exc)[:500],
        }
    return {
        "status": "completed", "provider": "openai_compatible_vision",
        "model": model, "observations": observations,
    }


async def extract_render_evidence(
    video_path: str, work_dir: str | Path, *, duration_seconds: float,
    includes_audio: bool, asr_api_key: str | None = None,
    asr_endpoint: str = "https://api.openai.com/v1/audio/transcriptions",
    asr_model: str = "whisper-1", vision_api_key: str | None = None,
    vision_endpoint: str = "https://api.openai.com/v1/chat/completions",
    vision_model: str = "gpt-4o-mini", timeout_seconds: int = 900,
) -> dict[str, Any]:
    root = Path(work_dir)
    frames = await extract_representative_keyframes(
        video_path, root / "frames", duration_seconds=duration_seconds,
        timeout_seconds=timeout_seconds,
    )
    evidence: dict[str, Any] = {
        "schema_version": "1.0", "extraction_status": "completed",
        "keyframes": frames, "transcript_segments": [],
        "visual_observations": [], "audio_observations": [],
        "transcription": {"status": "not_applicable" if not includes_audio else "not_configured",
                          "provider": None, "segments": []},
        "visual_semantics_status": "not_configured",
    }
    vision = await analyze_keyframes_with_vision(
        frames, root / "frames", api_key=vision_api_key,
        endpoint=vision_endpoint, model=vision_model, timeout_seconds=timeout_seconds,
    )
    evidence["visual_analysis"] = {
        "status": vision["status"], "provider": vision.get("provider"),
        "model": vision.get("model"), "message": vision.get("message"),
    }
    evidence["visual_semantics_status"] = vision["status"]
    evidence["visual_observations"] = vision.get("observations", [])
    if includes_audio:
        audio = await extract_audio_track(video_path, root / "audio.mp3", timeout_seconds)
        transcription = await transcribe_with_whisper(
            audio, api_key=asr_api_key, endpoint=asr_endpoint,
            model=asr_model, timeout_seconds=timeout_seconds,
        )
        evidence["transcription"] = transcription
        evidence["transcript_segments"] = transcription.get("segments", [])
        evidence["audio_artifact"] = {
            "filename": audio.name, "size_bytes": audio.stat().st_size,
            "codec": "mp3", "sample_rate_hz": 16000, "channels": 1,
        }
    return evidence
