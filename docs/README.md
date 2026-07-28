# SG-X Guardian Documentation

Use this page as the documentation entry point. Contract source material, delivery
acceptance, architecture, and historical references are kept separate so that
acceptance criteria can evolve without rewriting a signed SOW.

## Current delivery

- [Current SOW: Phase 2 Extension](sow/phase-2-extension/contract.md)
- [Deliverable tracker](deliverables/README.md)
- [Acceptance demo use cases](deliverables/acceptance/phase-2-extension-demo-use-cases.md)
- [Demo run record template](deliverables/acceptance/demo-run-template.md)

## Documentation map

| Area | Purpose |
| --- | --- |
| [Architecture](architecture/README.md) | System design and containerization assessments |
| [Decisions](decisions/README.md) | Current ADR index plus historical Phase 1 decision logs |
| [Deliverables](deliverables/README.md) | Delivery status, acceptance scenarios, and evidence records |
| [Reference](reference/README.md) | API, administrator, source, threat-model, and test artifacts |
| [Reviews](reviews/README.md) | Point-in-time engineering review notes |
| [SOW](sow/README.md) | Chronological, immutable scope source material |

## Conventions

- Do not add acceptance results to a contract. Contracts define scope;
  `deliverables/acceptance/` defines observable acceptance and records evidence.
- Use one demo run record per build, hardware set, and network profile.
- Keep current ADRs in `decisions/<number>-<slug>/README.md`. The two Phase 1
  monolithic logs are retained only as historical records.
- Put generated or point-in-time artifacts in `reference/` rather than at the
  `docs/` root.
