# Third-party software notices

This file records third-party software intentionally used by EDITFLOW AI or reviewed during engineering. It is not a claim that the listed projects are owned by EDITFLOW AI.

## Included as a runtime dependency

### PySceneDetect

- Upstream: https://github.com/Breakthrough/PySceneDetect
- Package: `scenedetect-headless`
- Version constraint: `>=0.7.3,<1`
- License: BSD 3-Clause
- Copyright: Copyright (C) 2014, Brandon Castellano
- Use in EDITFLOW AI: scene-boundary detection during timestamped render-evidence extraction.
- Integration: imported as an installed third-party package through `apps/api/requirements.txt`; upstream source is not copied or vendored.
- Local changes: EDITFLOW AI contains its own adapter in `apps/api/app/scene_detection.py`; no modifications are made to PySceneDetect itself.
- License text: [third_party/licenses/PYSCENEDETECT-BSD-3-CLAUSE.txt](third_party/licenses/PYSCENEDETECT-BSD-3-CLAUSE.txt)

## Engineering references reviewed; no source code copied or dependency added

These repositories were inspected for architectural ideas only. EDITFLOW AI does not redistribute their code as part of this integration.

### Kinocut

- Upstream: https://github.com/KyaniteLabs/kinocut
- Upstream license: Apache License 2.0
- Review purpose: agent-oriented FFmpeg workflows, guarded editing operations, and resumable workflow design.
- Integration status: reference only; no code copied, vendored, or installed.

### VidAPI

- Upstream: https://github.com/moshehbenavraham/vidapi
- Upstream license: MIT
- Review purpose: JSON timeline rendering API, worker separation, and S3-compatible artifact storage patterns.
- Integration status: reference only; no code copied, vendored, or installed.

## Existing system dependency requiring release-build review

### FFmpeg

- Upstream: https://ffmpeg.org/
- Use in EDITFLOW AI: media probing, extraction, rendering, and quality-control filters.
- Distribution note: FFmpeg's effective license depends on the exact build configuration and enabled external libraries. Before redistributing a packaged application/container outside the current deployment environment, record the deployed FFmpeg build configuration and include all applicable notices. Do not assume every FFmpeg build has identical licensing terms.

## Maintenance rules

1. Keep this file and the corresponding license texts with source distributions.
2. Re-check upstream license files and dependency versions before upgrades.
3. Generate and review a complete Software Bill of Materials (SBOM), including transitive Python and OS packages, before public commercial distribution.
4. Do not imply endorsement by upstream maintainers or use their names/logos as product endorsements.

### OpenCV-Python headless (transitive dependency)

- Upstream: https://github.com/opencv/opencv-python
- Package observed in the isolated worker SBOM: `opencv-python-headless 5.0.0.93`
- OpenCV library license: Apache-2.0 (OpenCV 4.5.0 and later).
- Wheel build scripts: MIT.
- Bundled FFmpeg libraries: LGPL-2.1, as stated by the upstream wheel project.
- Why present: transitive dependency of `scenedetect-headless`, installed only through `apps/api/requirements-worker.txt`; the headless wheel is appropriate for a server/container without GUI requirements.
- Important distinction: this wheel bundles its own FFmpeg shared libraries in addition to the separate Debian `ffmpeg` executable installed by the isolated worker Dockerfile. The bundled wheel libraries must be included in the worker release inventory separately from the worker's system FFmpeg package.

### FFmpeg in the isolated worker container (observed build snapshot)

- Container image source: `apps/api/Dockerfile` (Python 3.12.16 slim-trixie image pinned by immutable index digest; Debian 13 at the time of the refreshed build).
- Observed executable: FFmpeg `7.1.5-0+deb13u1`; FFprobe `7.1.5-0+deb13u1`.
- Observed configure flags include `--enable-gpl`, `--enable-libx264`, `--enable-libx265`, and `--enable-libxvid`; `--enable-version3` was not present.
- License consequence: this particular FFmpeg build is GPL-2.0-or-later, not an LGPL-only build. The FFmpeg project documents that enabling GPL components makes the resulting FFmpeg binaries/libraries GPL-covered. The exact Debian package copyright files and the SBOM must travel with any redistributed image.
- The isolated render worker invokes the standalone FFmpeg executable as a separate process; this fact alone does not mean EDITFLOW's Python application source is automatically relicensed. Redistribution of the FFmpeg executable/container still carries its own license and corresponding-source obligations.
- Reproducibility: the API and worker targets share the pinned Python 3.12.16 slim-trixie base by immutable image-index digest; only the worker target installs the exact Debian FFmpeg package version `7:7.1.5-0+deb13u1` from a dated Debian Snapshot. The next CI run must verify the refreshed base + snapshot combination and preserve the resulting SBOM and Debian copyright archive.
- CI preserves the CycloneDX container SBOM, license metadata inventory, exact FFmpeg build configuration, Debian package version list, and a tarball of installed Debian package copyright files as workflow artifacts.

### Licensing evidence

- FFmpeg legal/licensing guidance: https://www.ffmpeg.org/legal.html
- OpenCV-Python wheel licensing statement (including bundled FFmpeg LGPLv2.1): https://github.com/opencv/opencv-python#licensing
- OpenCV licensing (Apache-2.0 for OpenCV 4.5.0+): https://opencv.org/license/

## Web container and JavaScript dependency scope

- The web Dockerfile has a Node 22 Alpine build stage and an Nginx 1.30.6 Alpine 3.24 slim runtime stage; both base images are pinned by immutable image-index digests. The web Nginx process runs as UID 101 on unprivileged port 8080. CI generates separate SBOMs for both images so build-time npm dependencies are not hidden by the multi-stage runtime image.
- A reviewed `package-lock.json` is committed, and both the Dockerfile and CI use `npm ci` so npm dependency resolution is lockfile-driven.
- The Node and Nginx base image digests are pinned. The committed lockfile plus `npm ci` closes the previous web npm resolution gap; the lockfile still needs routine dependency vulnerability and license review.

## Build-time and runtime licenses confirmed from the full-stack SBOM

The inventory below was manually reconciled against upstream license texts where Syft did not return a license identifier. It remains a technical review record, not a legal opinion.

### Node.js build image and bundled build tooling

- Node.js `22.23.5`: MIT License ([upstream LICENSE](https://github.com/nodejs/node/blob/main/LICENSE)). The official Node.js license file also enumerates externally maintained components with separate licenses; preserve the license bundle captured by CI rather than assuming the whole Node distribution is covered by one MIT notice.
- esbuild `v0.0.0-20251101233416-208f539945b1`: MIT License ([upstream LICENSE](https://github.com/evanw/esbuild/blob/master/LICENSE)).
- `golang.org/x/sys` `v0.0.0-20220715151400-c0bba94af5f8`: BSD-3-Clause ([upstream license metadata](https://pkg.go.dev/golang.org/x/sys)).
- `editflow-story-graph-explorer@0.1.0` is the first-party private application package (`private: true`), not a third-party dependency. It is excluded from third-party license-missing counts; this does not grant or assert an open-source license for EDITFLOW AI itself.

### Reproducible container inputs pinned on the feature branch

- API base: `python:3.12.16-slim-trixie@sha256:4840d514c583a4d3d8cad3940e68dee6f0f6f3635c12fcd0a3d74c21a5b93a54` (index digest; refreshed on the feature branch).
- Web build base: `node:22-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a`.
- Web runtime base: `nginx:1.30.6-alpine3.24-slim@sha256:f65ed258206d1eb6c4eb6141111715a2cf94ac0a4ec9675fc2da186f7aadb163` (index digest; refreshed on the feature branch).
- Worker FFmpeg Debian package: `7:7.1.5-0+deb13u1` (version epoch included in the apt package pin).
- The Node build base remains pinned to the digest recorded in the current CI artifact. The Python and Nginx digest updates are proposed changes and must be verified by the next successful CI build and regenerated SBOM before they are treated as proven build inputs.

### Runtime separation and container hardening

- The Dockerfile now has separate `api` and `worker` targets. The API target excludes the FFmpeg/FFprobe executables and PySceneDetect/OpenCV dependencies; only the isolated worker target installs `requirements-worker.txt` and the media toolchain.
- Both Python runtime targets run as UID/GID 10001, not root.
- The production Compose topology sets read-only root filesystems, drops Linux capabilities, enables `no-new-privileges`, uses bounded writable tmpfs mounts, and applies PID/CPU/memory limits.
- The worker receives only database, object-storage, and optional evidence-extraction credentials; SMTP credentials and the API authentication secret are not inherited by the worker.
- The web Nginx runtime runs as UID 101 on port 8080. The public proxy is digest-pinned and has all capabilities dropped except `NET_BIND_SERVICE`.
- These controls reduce privilege and blast radius; they do not remove vulnerabilities in FFmpeg or guarantee that the application cannot be compromised. The worker image remains blocked until its own scan is clean or the vulnerable media-processing dependency is replaced with a demonstrably safer design.

### API development-only dependencies

- `pytest` and `pytest-asyncio` are in `apps/api/requirements-dev.txt`, which includes the production `requirements.txt`; they are no longer installed into the production API image.
- CI installs the development requirements for test execution. The production Dockerfile installs only `apps/api/requirements.txt`.

### Remaining reproducibility limitation

- Python production requirements still use semver-like version ranges (`>=` / `<`) without a committed hash-locked resolver file. The SBOM records one resolved build, but Python dependency resolution is not fully reproducible yet. Add a reviewed Python lock/constraints file with hashes and install it with a deterministic pip workflow before claiming end-to-end dependency reproducibility.


### Container vulnerability scanning

- CI now runs Trivy against the API, isolated worker, and web production images using a pinned Trivy Action commit and Trivy scanner version. All severity levels are included, and any known finding fails the gate.
- Any known finding at UNKNOWN, LOW, MEDIUM, HIGH, or CRITICAL severity (including unfixed findings) fails the container security gate; the JSON reports are uploaded for review even when the gate fails.
- A green security gate is not established until the updated image build and scan job complete successfully. Do not suppress findings without a documented rationale, scope assessment, and time-bounded exception.
