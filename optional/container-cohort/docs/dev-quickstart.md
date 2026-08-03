# SG-X Guardian Optional Container Cohort

## Start
```bash
./optional/container-cohort/up.sh
```

## Status
```bash
./optional/container-cohort/ps.sh
```

## Live logs
```bash
./optional/container-cohort/logs.sh nodeA
./optional/container-cohort/logs.sh nodeB
./optional/container-cohort/logs.sh nodeC
```

## Quick checks
```bash
curl -s http://localhost:18443/api/v1/crl/root
curl -s http://localhost:28443/api/v1/crl/root
curl -s http://localhost:38443/api/v1/crl/root
docker exec sgx-nodeB sgx-pa-cli crl root
docker exec sgx-nodeC sgx-pa-cli crl root
```

## Stop
```bash
./optional/container-cohort/down.sh
```
