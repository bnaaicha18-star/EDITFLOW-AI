"""Deterministic FFmpeg command planning from an immutable timeline snapshot.

This module only plans commands. It does not execute FFmpeg, download assets, or
upload outputs; those are deliberately separate worker/storage adapters.
"""
from __future__ import annotations

from dataclasses import dataclass
from math import isfinite
from typing import Mapping, Any

from app.media_policy import media_input_args


class RenderPlanError(ValueError):
    """The timeline or render profile cannot be represented by the MVP renderer."""


@dataclass(frozen=True)
class RenderPlan:
    argv: tuple[str, ...]
    output_path: str
    duration_seconds: float
    input_asset_ids: tuple[str, ...]
    includes_audio: bool
    width: int | None = None
    height: int | None = None
    fps: float | None = None


def _positive_number(value: Any, field: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise RenderPlanError(f"{field} must be a number") from None
    if not isfinite(number) or number <= 0:
        raise RenderPlanError(f"{field} must be greater than zero")
    return number


def build_ffmpeg_plan(
    timeline_snapshot: Mapping[str, Any],
    asset_paths: Mapping[str, str],
    output_path: str,
    render_profile: Mapping[str, Any] | None = None,
    asset_has_audio: Mapping[str, bool] | None = None,
) -> RenderPlan:
    """Build a shell-free FFmpeg argv from a pinned timeline snapshot."""
    profile = dict(render_profile or {})
    sequence = dict(timeline_snapshot.get("sequence") or {})
    width = int(profile.get("width", sequence.get("width", 1080)))
    height = int(profile.get("height", sequence.get("height", 1920)))
    fps = _positive_number(profile.get("fps", sequence.get("fps", 30)), "fps")
    if width < 2 or height < 2 or width > 7680 or height > 7680:
        raise RenderPlanError("width and height must be between 2 and 7680")
    if width % 2 or height % 2:
        raise RenderPlanError("width and height must be even for yuv420p output")
    if fps > 120:
        raise RenderPlanError("fps cannot exceed 120")
    if not output_path or not output_path.strip():
        raise RenderPlanError("output_path is required")
    preset = str(profile.get("preset", "medium"))
    if preset not in {"ultrafast", "superfast", "veryfast", "faster", "fast", "medium", "slow", "slower", "veryslow"}:
        raise RenderPlanError("preset is not an allowed libx264 preset")
    try:
        crf = int(profile.get("crf", 20))
    except (TypeError, ValueError):
        raise RenderPlanError("crf must be an integer from 0 to 51") from None
    if crf < 0 or crf > 51:
        raise RenderPlanError("crf must be an integer from 0 to 51")
    clips = list(timeline_snapshot.get("clips") or [])
    if not clips:
        raise RenderPlanError("Cannot render a timeline with no clips")

    ordered = sorted(clips, key=lambda clip: (float(clip.get("timeline_start", 0)), str(clip.get("id", ""))))
    inputs, filters, asset_ids, audio_labels, end_times = [], [], [], [], []
    audio_map = asset_has_audio or {}
    for index, clip in enumerate(ordered):
        asset_id = str(clip.get("asset_id", ""))
        if not asset_id:
            raise RenderPlanError(f"clip {index} is missing asset_id")
        source_path = asset_paths.get(asset_id)
        if not source_path:
            raise RenderPlanError(f"No resolved media path for asset {asset_id}")
        if clip.get("transform"):
            raise RenderPlanError("Custom clip transforms are not supported by the MVP renderer")
        source_in, source_out, start = (float(clip.get(k, default)) for k, default in
                                        (("source_in", 0), ("source_out", 0), ("timeline_start", 0)))
        if not all(isfinite(v) for v in (source_in, source_out, start)) or source_in < 0 or start < 0 or source_out <= source_in:
            raise RenderPlanError(f"clip {index} has invalid timing")
        duration = source_out - source_in
        end_times.append(start + duration)
        inputs.extend(media_input_args(source_path))
        filters.append(
            f"[{index}:v:0]trim=start={source_in}:duration={duration},"
            f"setpts=PTS-STARTPTS,fps={fps},"
            f"scale={width}:{height}:force_original_aspect_ratio=decrease,"
            f"pad={width}:{height}:(ow-iw)/2:(oh-ih)/2:color=black,"
            f"setsar=1,format=yuv420p[v{index}]"
        )
        if audio_map.get(asset_id, False):
            gain = float(clip.get("audio_gain_db", 0))
            if not isfinite(gain) or gain < -60 or gain > 24:
                raise RenderPlanError(f"clip {index} audio_gain_db must be between -60 and 24")
            delay_ms = round(start * 1000)
            filters.append(
                f"[{index}:a:0]atrim=start={source_in}:duration={duration},"
                f"asetpts=PTS-STARTPTS,volume={gain}dB,"
                f"adelay={delay_ms}|{delay_ms}[a{index}]"
            )
            audio_labels.append(f"[a{index}]")
        asset_ids.append(asset_id)

    total_duration = max(end_times)
    filters.insert(0, f"color=c=black:s={width}x{height}:r={fps}:d={total_duration},format=yuv420p[base0]")
    current = "base0"
    for index, clip in enumerate(ordered):
        start = float(clip.get("timeline_start", 0))
        end = start + float(clip.get("source_out", 0)) - float(clip.get("source_in", 0))
        next_label = f"base{index + 1}"
        filters.append(f"[{current}][v{index}]overlay=0:0:eof_action=pass:enable='between(t,{start},{end})'[{next_label}]")
        current = next_label
    filters.append(f"[{current}]trim=duration={total_duration},setpts=PTS-STARTPTS[vout]")
    includes_audio = bool(audio_labels)
    if includes_audio:
        filters.append("".join(audio_labels) + f"amix=inputs={len(audio_labels)}:duration=longest:normalize=0,atrim=duration={total_duration}[aout]")
    argv = ["ffmpeg", "-hide_banner", "-nostdin", "-y", *inputs,
            "-filter_complex", ";".join(filters), "-map", "[vout]"]
    if includes_audio:
        argv.extend(["-map", "[aout]", "-c:a", "aac", "-b:a", "192k"])
    else:
        argv.append("-an")
    argv.extend(["-c:v", "libx264", "-preset", preset, "-crf", str(crf),
                 "-pix_fmt", "yuv420p", "-r", str(fps), "-movflags", "+faststart",
                 "-t", str(total_duration), output_path])
    return RenderPlan(
        argv=tuple(argv), output_path=output_path, duration_seconds=total_duration,
        input_asset_ids=tuple(asset_ids), includes_audio=includes_audio,
        width=width, height=height, fps=fps,
    )
