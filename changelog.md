## v1.8.4

Changes since v1.8.3:
* fix: make clippy happy
* Refactor OverlayFS implementation
* fix: retry overlay mount with simple options on failure
* fix: correct logic for ZygiskSU enforce status check
* chore(deps-dev): bump svelte-check from 4.3.4 to 4.3.5 in /webui
* chore(deps): bump zip from 6.0.0 to 7.0.0
* chore(deps): bump tracing from 0.1.43 to 0.1.44
* chore(deps): bump toml from 0.9.8 to 0.9.10+spec-1.1.0
* chore(deps): bump serde_json from 1.0.145 to 1.0.146
* fix(executor): refine hymofs injection granularity to prevent bootloops
* fix: make clippy happy
* feat(hymofs): adapt to upstream v7 protocol with syscall hook and merge rules
* chore(release): bump version to v1.8.3 [skip ci]
* [skip ci]workflow(release): remove clippy check