# SG-X Guardian - Containers

## Roles
1. `docker/Dockerfile.agent`: reproducible x86_64 build and test image.
2. `docker/Dockerfile.board-builder`: pinned aarch64 builder for board-ready binaries.
3. `docker-compose.dev.yml`: three-node dev/demo cohort on one machine.

## Quickstart - board binaries
```bash
docker build -f docker/Dockerfile.board-builder -t sgx-board-builder .
docker run --rm -v "$PWD":/src -v "$PWD/artifacts":/artifacts sgx-board-builder
scp artifacts/sgx-guardian root@192.168.50.101:/path/on/board/sgx_guardian_client
```

On the board, continue with the usual native flow:

```bash
pkill -f sgx_guardian_client || true
./sgx_guardian_client nodeA
```

## Quickstart - dev cohort
```bash
docker compose -f docker-compose.dev.yml up --build -d
docker compose -f docker-compose.dev.yml logs -f nodeA
curl -s http://localhost:18443/api/v1/crl/root
docker exec sgx-nodeB sgx-pa-cli crl root
```

## Production note
Boards continue to run the native binary. These container assets are for build
reproducibility, CI, and the local multi-node cohort.

## Windows / Docker Desktop
The cohort is designed for Linux containers under Docker Desktop / WSL2. If
bind-mounted builds are slow, prefer a named volume for `/src/target`.

## Troubleshooting
- If `nodeA` never becomes healthy, inspect `docker logs sgx-nodeA` for the startup step markers.
- If member bootstrap fails, confirm `SGX_LIGHTHOUSE_IP=172.31.250.10` and that `nodeA` is healthy first.
- If `nebula0` is missing, verify `NET_ADMIN` and `/dev/net/tun` are available.
- If you want to exercise nftables enforcement in the cohort, remove `SGX_DISABLE_POLICY_ENFORCEMENT` for one node first.
