# Optional Container Cohort

This folder contains the laptop-only Docker cohort.

- Keep this folder in the repo if you want the 3-node containerized setup.
- Remove this folder from the repo if you want the project to behave like a normal board/native checkout.

Board/native code stays outside this folder and does not depend on it at runtime.

## Prerequisites
- These helpers require a working Docker daemon plus `docker compose`.
- On WSL 2 with Docker Desktop, enable Docker Desktop -> Settings -> Resources -> WSL Integration for this distro before running the helper scripts.
- From the repo root use `./optional/container-cohort/up.sh`; from inside the folder use `./up.sh`. `/optional/container-cohort/up.sh` is not a valid path on Linux unless that directory exists at the filesystem root.
- The virtual Docker cohort keeps `/etc/sgx-guardian` in named volumes. After a rebuild, you may briefly see a PCR3 `RootFS` mismatch in the logs; the virtual startup path now refreshes that dev baseline automatically and continues booting.

## Base vs overlay
- Root project is intended to stay on the older base containerization flow.
- `optional/container-cohort/overlay/` holds the newer laptop-only source changes.
- `optional/container-cohort/docker/Dockerfile.agent` copies that overlay on top of the root tree only during Docker image build.

So:
- board/native run uses the root project only
- laptop Docker cohort uses `root + optional overlay`

## Commands
```bash
./optional/container-cohort/up.sh
./optional/container-cohort/ps.sh
./optional/container-cohort/logs.sh nodeA
./optional/container-cohort/down.sh
```

Detailed runbook:

- [optional/container-cohort/docs/CONTAINERS.md](/home/asad/SGX/optional/container-cohort/docs/CONTAINERS.md:1)
- [optional/container-cohort/docs/Containerization.md](/home/asad/SGX/optional/container-cohort/docs/Containerization.md:1)

## Optional CI note
If you also want the container workflow back in GitHub Actions, the saved workflow copy is here:

```text
optional/container-cohort/workflows/containers.yml
```
