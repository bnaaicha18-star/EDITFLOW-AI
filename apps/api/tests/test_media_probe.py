import asyncio
import json

import pytest

from app.media_probe import MediaProbeError, probe_media


class FakeProcess:
    def __init__(self, payload, returncode=0, stderr=b""):
        self.payload = payload
        self.returncode = returncode
        self.stderr = stderr

    async def communicate(self):
        return json.dumps(self.payload).encode(), self.stderr

    def kill(self):
        pass


@pytest.mark.asyncio
async def test_probe_media_reports_video_and_audio_streams_and_enforces_parser_policy(monkeypatch):
    captured = {}

    async def fake_create(*args, **kwargs):
        captured["args"] = args
        return FakeProcess({
            "format": {"duration": "12.5", "format_name": "mov,mp4,m4a,3gp,3g2,mj2"},
            "streams": [
                {"codec_type": "video", "codec_name": "h264", "width": 1080, "height": 1920},
                {"codec_type": "audio", "codec_name": "aac"},
            ],
        })

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create)
    info = await probe_media("/media/sample.mp4")
    assert info.duration_seconds == 12.5
    assert info.has_video is True
    assert info.has_audio is True
    assert info.width == 1080
    assert info.height == 1920
    assert info.format_name == "mov,mp4,m4a,3gp,3g2,mj2"
    args = list(captured["args"])
    assert args[args.index("-protocol_whitelist") + 1] == "file,pipe"
    assert args[args.index("-format_whitelist") + 1] == "mov,matroska"
    assert "cfhd" not in args[args.index("-codec_whitelist") + 1]
    assert args[-1] == "/media/sample.mp4"


@pytest.mark.asyncio
async def test_probe_media_rejects_audio_only_input(monkeypatch):
    async def fake_create(*args, **kwargs):
        return FakeProcess({
            "format": {"duration": "4"},
            "streams": [{"codec_type": "audio", "codec_name": "aac"}],
        })

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create)
    with pytest.raises(MediaProbeError, match="no video stream"):
        await probe_media("/media/audio.m4a")


@pytest.mark.asyncio
async def test_probe_media_rejects_unsupported_video_codec(monkeypatch):
    async def fake_create(*args, **kwargs):
        return FakeProcess({
            "format": {"duration": "4", "format_name": "mov,mp4,m4a,3gp,3g2,mj2"},
            "streams": [{"codec_type": "video", "codec_name": "cfhd", "width": 1920, "height": 1080}],
        })

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create)
    with pytest.raises(MediaProbeError, match="Unsupported video codec"):
        await probe_media("/media/cineform.mp4")


@pytest.mark.asyncio
async def test_probe_media_surfaces_ffprobe_error(monkeypatch):
    async def fake_create(*args, **kwargs):
        return FakeProcess({}, returncode=1, stderr=b"invalid file")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create)
    with pytest.raises(MediaProbeError, match="invalid file"):
        await probe_media("/media/broken.mp4")
