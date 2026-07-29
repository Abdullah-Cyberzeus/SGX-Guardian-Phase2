# Record single-producer cache results

- Record five 2-second shared Cargo registry restores with no consumer post-save hooks or reserve warnings.
- Confirm Unit Tests skipped the sole producer step on an exact hit and the cache API retained one 52.8 MiB main entry without a PR-scoped duplicate.
- Attribute the direct warm saving to two runner-seconds of removed post steps; do not claim the variable full-workflow duration as a cache speedup.
