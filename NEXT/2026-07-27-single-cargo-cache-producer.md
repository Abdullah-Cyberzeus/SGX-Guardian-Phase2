# Remove parallel Cargo cache save races

- Keep one shared Cargo registry key so every Linux validation job can reuse the same 52.8 MiB cache.
- Make all five parallel Linux jobs restore-only and let successful Unit Tests save a missing primary key once.
- Avoid per-job suffixes, which would fragment cross-job reuse and increase equivalent registry storage from about 52.8 MiB to about 264.2 MiB.
- Add a static workflow fixture that enforces five shared restores and exactly one Unit Tests producer.
