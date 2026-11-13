# Open-source intake and attribution policy

## Rules for EDITFLOW AI

- Prefer maintained dependencies with an explicit OSI-approved license and a clear upstream repository.
- Prefer consuming libraries through pinned package dependencies over copying source files.
- Do not copy code from repositories with no license or unclear licensing.
- Before adopting a dependency, review its license, release activity, security posture, transitive dependencies, and compatibility with commercial distribution.
- Preserve required copyright notices, license texts, attribution notices, and NOTICE files.
- Keep upstream code separate from EDITFLOW-owned adapters and modifications.
- Record the exact upstream URL, package/version, license, purpose, and whether code was copied, modified, or only studied in `THIRD_PARTY_NOTICES.md`.
- Do not claim upstream authors endorse EDITFLOW AI.
- Run tests and dependency/security checks after each adoption.

## Current adoption decision

PySceneDetect is adopted as an external BSD-3-Clause dependency for scene-boundary detection. Kinocut and VidAPI were reviewed as architecture references only; no code from them is included.
