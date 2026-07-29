# SG-X Guardian Documentation

Use this page as the documentation entry point. Each SOW keeps its deliverable
tracking and acceptance material beside the scope it governs.

## Current delivery

- [Current SOW: Phase 2 Extension](sow/phase-2-extension/contract.md)
- [Phase 2 Extension deliverable tracker](sow/phase-2-extension/deliverables/README.md)
- [Acceptance demo use cases](sow/phase-2-extension/deliverables/acceptance/demo-use-cases.md)
- [Demo run record template](sow/phase-2-extension/deliverables/acceptance/demo-run-template.md)

## Documentation map

| Area | Purpose |
| --- | --- |
| [Architecture](architecture/README.md) | System design and containerization assessments |
| [Decisions](decisions/README.md) | Current ADR index plus historical Phase 1 decision logs |
| [Reference](reference/README.md) | API, administrator, source, threat-model, and test artifacts |
| [Reviews](reviews/README.md) | Point-in-time engineering review notes |
| [SOW and deliverables](sow/README.md) | Scope, deliverable tracking, acceptance scenarios, and evidence records by phase |

## Conventions

- Keep each phase's deliverables and acceptance evidence under that phase's SOW
  directory.
- Do not add acceptance results to a contract. Contracts define scope; the
  phase's `deliverables/acceptance/` directory defines observable acceptance and
  records evidence.
- Use one demo run record per build, hardware set, and network profile.
- Keep current ADRs in `decisions/<number>-<slug>/README.md`. The two Phase 1
  monolithic logs are retained only as historical records.
- Put generated or point-in-time artifacts in `reference/` rather than at the
  `docs/` root.
