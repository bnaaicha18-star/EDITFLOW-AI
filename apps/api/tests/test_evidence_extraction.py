import asyncio
from pathlib import Path

import pytest

from app.evidence_extraction import extract_render_evidence
from app.qc_critic import generate_qc_critic_proposals


@pytest.mark.asyncio
async def test_extracts_timestamped_keyframes_and_audio_artifact(tmp_path):
    source = tmp_path / "source.mp4"
    process = await asyncio.create_subprocess_exec(
        "ffmpeg", "-hide_banner", "-loglevel", "error", "-nostdin",
        "-f", "lavfi", "-i", "testsrc=size=320x240:rate=10:duration=3",
        "-f", "lavfi", "-i", "sine=frequency=1000:duration=3",
        "-shortest", "-c:v", "libx264", "-pix_fmt", "yuv420p",
        "-c:a", "aac", "-y", str(source),
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await process.communicate()
    assert process.returncode == 0, stderr.decode("utf-8", errors="replace")

    evidence = await extract_render_evidence(
        str(source), tmp_path / "evidence",
        duration_seconds=3.0, includes_audio=True, asr_api_key=None,
    )
    assert evidence["extraction_status"] == "completed"
    assert evidence["keyframes"]
    assert all((tmp_path / "evidence" / "frames" / item["filename"]).is_file()
               for item in evidence["keyframes"])
    assert evidence["transcription"]["status"] == "not_configured"
    assert evidence["transcript_segments"] == []
    assert (tmp_path / "evidence" / "audio.mp3").is_file()
    assert evidence["audio_artifact"]["sample_rate_hz"] == 16000


def test_critic_receives_timestamped_extracted_keyframes_and_transcript():
    report = {
        "findings": [{"code": "frozen_scene", "start_seconds": 2, "end_seconds": 4}],
        "evidence": {
            "keyframes": [
                {"timestamp_seconds": 1, "end_seconds": 2, "object_key": "frames/a.jpg"},
                {"timestamp_seconds": 2.5, "end_seconds": 3, "object_key": "frames/b.jpg",
                 "sample_type": "scene_change"},
            ],
            "transcript_segments": [
                {"start_seconds": 2.2, "end_seconds": 2.8, "text": "Look at this."},
            ],
        },
    }
    proposal = generate_qc_critic_proposals(report, {})["proposals"][0]
    evidence = proposal["temporal_evidence"]
    assert len(evidence["keyframes"]) == 1
    assert evidence["keyframes"][0]["object_key"] == "frames/b.jpg"
    assert evidence["transcript_segments"][0]["text"] == "Look at this."


@pytest.mark.asyncio
async def test_scene_detection_failure_falls_back_to_ffmpeg(monkeypatch):
    import app.evidence_extraction as extraction

    class FailedDetector:
        returncode = 1

        async def communicate(self):
            return b"", b"PySceneDetect failed"

    async def fake_create_subprocess_exec(*args, **kwargs):
        return FailedDetector()

    async def fake_fallback(video_path, threshold, timeout_seconds):
        assert video_path == "broken-codec.mp4"
        assert threshold == 0.3
        assert timeout_seconds == 7
        return [1.25]

    monkeypatch.setattr(extraction.asyncio, "create_subprocess_exec", fake_create_subprocess_exec)
    monkeypatch.setattr(extraction, "_ffmpeg_scene_change_timestamps", fake_fallback)

    result = await extraction._scene_change_timestamps("broken-codec.mp4", 0.3, 7)
    assert result == [1.25]


@pytest.mark.asyncio
async def test_scene_detection_timeout_kills_subprocess_and_falls_back(monkeypatch):
    import app.evidence_extraction as extraction

    class SlowDetector:
        returncode = None
        killed = False
        calls = 0

        async def communicate(self):
            self.calls += 1
            if self.calls == 1:
                await asyncio.sleep(3)
                return b"", b""
            return b"", b""

        def kill(self):
            self.killed = True
            self.returncode = -9

    process = SlowDetector()

    async def fake_create_subprocess_exec(*args, **kwargs):
        return process

    async def fake_fallback(video_path, threshold, timeout_seconds):
        return [2.0]

    monkeypatch.setattr(extraction.asyncio, "create_subprocess_exec", fake_create_subprocess_exec)
    monkeypatch.setattr(extraction, "_ffmpeg_scene_change_timestamps", fake_fallback)

    result = await extraction._scene_change_timestamps("slow.mp4", 0.3, 0)
    assert result == [2.0]
    assert process.killed is True

@pytest.mark.asyncio
async def test_scene_detection_cancellation_kills_subprocess_and_propagates(monkeypatch):
    import app.evidence_extraction as extraction

    class CancellableDetector:
        returncode = None
        killed = False
        calls = 0

        async def communicate(self):
            self.calls += 1
            if self.calls == 1:
                await asyncio.Future()
            return b"", b""

        def kill(self):
            self.killed = True
            self.returncode = -9

    process = CancellableDetector()

    async def fake_create_subprocess_exec(*args, **kwargs):
        return process

    async def unexpected_fallback(*args, **kwargs):
        raise AssertionError("Cancellation must not start FFmpeg fallback")

    monkeypatch.setattr(extraction.asyncio, "create_subprocess_exec", fake_create_subprocess_exec)
    monkeypatch.setattr(extraction, "_ffmpeg_scene_change_timestamps", unexpected_fallback)

    task = asyncio.create_task(extraction._scene_change_timestamps("cancel.mp4", 0.3, 30))
    await asyncio.sleep(0)
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task

    assert process.killed is True
    assert process.calls == 2
