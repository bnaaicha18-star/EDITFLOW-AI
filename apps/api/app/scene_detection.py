"""Scene-boundary detection adapter backed by the BSD-3-Clause PySceneDetect library.

EDITFLOW owns this adapter; PySceneDetect is installed as an external dependency.
No upstream source files are copied or vendored into this repository.
"""
from __future__ import annotations

import math
from pathlib import Path


class SceneDetectionError(RuntimeError):
    """Raised when PySceneDetect cannot inspect the supplied media."""


def detect_scene_changes(video_path: str, threshold: float = 0.30) -> list[float]:
    """Return scene start times (excluding the first scene) in seconds.

    The public EDITFLOW threshold remains in the 0.05..0.95 range used by the
    previous FFmpeg scene filter. It is scaled to PySceneDetect's 0..100
    ContentDetector threshold convention.
    """
    if not 0.05 <= threshold <= 0.95:
        raise ValueError("threshold must be between 0.05 and 0.95")
    if not Path(video_path).is_file():
        raise SceneDetectionError("Video file does not exist")

    try:
        from scenedetect import SceneManager, open_video
        from scenedetect.detectors import ContentDetector

        video = open_video(str(video_path))
        manager = SceneManager()
        # Preserve the previous FFmpeg detector's ability to report short scenes;
        # PySceneDetect's default 15-frame minimum can hide cuts in short clips.
        manager.add_detector(ContentDetector(threshold=threshold * 100.0, min_scene_len=1))
        manager.detect_scenes(video, show_progress=False)
        scenes = manager.get_scene_list()
        boundaries = [float(start.get_seconds()) for start, _end in scenes[1:]]
        return sorted(value for value in boundaries if math.isfinite(value) and value >= 0)
    except Exception as exc:
        raise SceneDetectionError(f"PySceneDetect failed: {type(exc).__name__}: {exc}") from exc
