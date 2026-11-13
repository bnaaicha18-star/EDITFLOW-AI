"""Strict allowlists for untrusted media parsed by FFmpeg/FFprobe.

The product accepts MP4/MOV/WebM containers only. These controls deliberately
limit demuxers, protocols, and codecs before any media parser is invoked.
"""
from __future__ import annotations

MEDIA_DEMUXER_WHITELIST = "mov,matroska"
MEDIA_PROTOCOL_WHITELIST = "file,pipe"
MEDIA_CODEC_WHITELIST = (
    "h264,hevc,vp8,vp9,av1,prores,mpeg4,mjpeg,"
    "aac,mp3,opus,vorbis,pcm_s16le,pcm_s24le,alac,ac3,eac3,flac"
)
SUPPORTED_VIDEO_CODECS = frozenset({
    "h264", "hevc", "vp8", "vp9", "av1", "prores", "mpeg4", "mjpeg",
})
SUPPORTED_AUDIO_CODECS = frozenset({
    "aac", "mp3", "opus", "vorbis", "pcm_s16le", "pcm_s24le",
    "alac", "ac3", "eac3", "flac",
})


def media_input_options() -> list[str]:
    """FFmpeg input options for uploaded MP4/MOV/WebM assets."""
    return [
        "-protocol_whitelist", MEDIA_PROTOCOL_WHITELIST,
        "-format_whitelist", MEDIA_DEMUXER_WHITELIST,
        "-codec_whitelist", MEDIA_CODEC_WHITELIST,
        "-max_alloc", "268435456",
        "-probesize", "10000000",
        "-analyzeduration", "10000000",
    ]


def media_input_args(path: str) -> list[str]:
    """Input options plus an input path, for FFmpeg's per-input option scope."""
    return [*media_input_options(), "-i", str(path)]
