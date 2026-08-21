# SG-X Guardian - Containers

## Purpose
This runbook is for the laptop Docker cohort.

- `nodeA` = CA / owner / lighthouse
- `nodeB` = member
- `nodeC` = member
- cohort assets live under `optional/container-cohort/`

## Prerequisites
- Docker daemon must be reachable from the shell that runs these helpers.
- On WSL 2 with Docker Desktop, enable Docker Desktop -> Settings -> Resources -> WSL Integration for this distro, then open a fresh WSL shell.
- From the repo root run `./optional/container-cohort/start.sh`; from inside `optional/container-cohort/` run `./start.sh`. `/optional/container-cohort/start.sh` is an absolute path and will fail unless that directory exists directly under `/`.

## Paths And Ports
Run these helper scripts from the repo root:

```bash
./optional/container-cohort/up.sh
./optional/container-cohort/start.sh
./optional/container-cohort/stop.sh
./optional/container-cohort/down.sh
./optional/container-cohort/ps.sh
./optional/container-cohort/logs.sh nodeA
```

Host REST ports:

- `nodeA` -> `http://localhost:18443`
- `nodeB` -> `http://localhost:28443`
- `nodeC` -> `http://localhost:38443`

Container names:

- `sgx-nodeA`
- `sgx-nodeB`
- `sgx-nodeC`

## Lifecycle Commands
First build + create + start all three nodes:

```bash
./optional/container-cohort/up.sh
```

Start already-created stopped containers:

```bash
./optional/container-cohort/start.sh
```

Stop running containers without deleting them:

```bash
./optional/container-cohort/stop.sh
```

Stop and remove containers + compose network:

```bash
./optional/container-cohort/down.sh
```

Show current container status:

```bash
./optional/container-cohort/ps.sh
```

Raw compose equivalents:

```bash
docker compose -f optional/container-cohort/docker-compose.dev.yml up --build -d
docker compose -f optional/container-cohort/docker-compose.dev.yml start
docker compose -f optional/container-cohort/docker-compose.dev.yml stop
docker compose -f optional/container-cohort/docker-compose.dev.yml down
docker compose -f optional/container-cohort/docker-compose.dev.yml ps
```

Full fresh reset, including named volumes:

```bash
docker compose -f optional/container-cohort/docker-compose.dev.yml down -v
```

## Logs
Follow helper-script logs:

```bash
./optional/container-cohort/logs.sh nodeA
./optional/container-cohort/logs.sh nodeB
./optional/container-cohort/logs.sh nodeC
```

Live Docker logs:

```bash
docker logs -f sgx-nodeA
docker logs -f sgx-nodeB
docker logs -f sgx-nodeC
```

Last 100 lines + follow:

```bash
docker logs --tail=100 -f sgx-nodeA
docker logs --tail=100 -f sgx-nodeB
docker logs --tail=100 -f sgx-nodeC
```

Quick state check:

```bash
docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
```

## Open A Shell In Any Node
Open interactive shell:

```bash
docker exec -it sgx-nodeA sh
docker exec -it sgx-nodeB sh
docker exec -it sgx-nodeC sh
```

Important:

- `docker exec ...` host machine par chalta hai
- agar tum pehle se container ke andar ho, wahan `docker exec` mat chalao

## Run Commands On Specific Nodes
Single shell command on `nodeA`:

```bash
docker exec sgx-nodeA sh -lc 'cat /var/lib/sgx-guardian/identity/did.json'
```

Single shell command on `nodeB`:

```bash
docker exec sgx-nodeB sh -lc 'cat /var/lib/sgx-guardian/identity/did.json'
```

Single shell command on `nodeC`:

```bash
docker exec sgx-nodeC sh -lc 'cat /var/lib/sgx-guardian/identity/did.json'
```

`sgx-pa-cli` command on `nodeA`:

```bash
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeA sgx-pa-cli crl root
```

`sgx-pa-cli` command on `nodeB`:

```bash
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeB sgx-pa-cli crl root
```

`sgx-pa-cli` command on `nodeC`:

```bash
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeC sgx-pa-cli crl root
```

Useful examples:

```bash
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeA sgx-pa-cli crl list
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeB sgx-pa-cli crl list
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeC sgx-pa-cli crl list
```

```bash
docker exec sgx-nodeA sh -lc 'ls -R /var/lib/sgx-guardian/identity | sed -n "1,120p"'
docker exec sgx-nodeB sh -lc 'ls -R /var/lib/sgx-guardian/identity | sed -n "1,120p"'
docker exec sgx-nodeC sh -lc 'ls -R /var/lib/sgx-guardian/identity | sed -n "1,120p"'
```

## REST API From Host
Node A:

```bash
curl -s http://localhost:18443/api/v1/crl/root
curl -s http://localhost:18443/api/v1/crl/list | python3 -m json.tool
```

Node B:

```bash
curl -s http://localhost:28443/api/v1/crl/root
curl -s http://localhost:28443/api/v1/crl/list | python3 -m json.tool
```

Node C:

```bash
curl -s http://localhost:38443/api/v1/crl/root
curl -s http://localhost:38443/api/v1/crl/list | python3 -m json.tool
```

## Common Flow
Normal day-to-day flow:

1. `./optional/container-cohort/up.sh`
2. `./optional/container-cohort/ps.sh`
3. `docker logs -f sgx-nodeA`
4. `docker logs -f sgx-nodeB`
5. `docker logs -f sgx-nodeC`
6. `docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeA sgx-pa-cli ...`
7. `curl -s http://localhost:18443/api/v1/...`

## Verification Logs

- [Task 1 AI - Docker Verification Log](/home/asad/SGX/optional/container-cohort/docs/Task1_AI_Docker_Verification_Log.md:1)

## Troubleshooting
- Agar `nodeA` healthy na ho, pehle `docker logs --tail=200 sgx-nodeA` dekho.
- Agar `nodeB` ya `nodeC` bootstrap par ruk jayein, confirm karo `nodeA` healthy hai.
- `sgx-pa-cli` ko `docker exec` se chalate waqt `-e SGX_FORCE_SOFTWARE_KEYS=1` use karo.
- Fresh cert/bootstrap test ke liye named volumes bhi clean karni par sakti hain: `docker compose -f optional/container-cohort/docker-compose.dev.yml down -v`
- Rebuilt virtual images may log one PCR3 `RootFS` mismatch on startup because the saved dev baseline lives in the named `/etc/sgx-guardian` volume. The container cohort now refreshes that virtual baseline automatically after the mismatch is detected.
- Agar `nebula0` na bane to `/dev/net/tun` aur `NET_ADMIN` availability verify karo.
- Agar container ke andar `python3` na mile, host side par `docker exec ... | python3 -m json.tool` use karo.
