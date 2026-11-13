import asyncio

import pytest

from app.scene_detection import detect_scene_changes


@pytest.mark.asyncio
async def test_detects_boundary_between_two_distinct_scenes(tmp_path):
    source = tmp_path / "two-scenes.mp4"
    process = await asyncio.create_subprocess_exec(
        "ffmpeg", "-hide_banner", "-loglevel", "error", "-nostdin",
        "-f", "lavfi", "-i", "color=c=red:s=160x120:r=10:d=1",
        "-f", "lavfi", "-i", "color=c=blue:s=160x120:r=10:d=1",
        "-filter_complex", "[0:v][1:v]concat=n=2:v=1:a=0,format=yuv420p[v]",
        "-map", "[v]", "-c:v", "libx264", "-y", str(source),
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await process.communicate()
    assert process.returncode == 0, stderr.decode("utf-8", errors="replace")

    boundaries = await asyncio.to_thread(detect_scene_changes, str(source), 0.30)
    assert boundaries
    assert any(0.6 <= timestamp <= 1.4 for timestamp in boundaries)


def test_rejects_invalid_threshold(tmp_path):
    source = tmp_path / "unused.mp4"
    source.write_bytes(b"not a video")
    with pytest.raises(ValueError, match="threshold"):
        detect_scene_changes(str(source), 1.5)
