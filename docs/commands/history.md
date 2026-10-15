# history

`crabbox history` lists recorded remote command runs from the broker. Each run is
created by [`crabbox run`](run.md) (and run-backed flows such as
[`crabbox job run`](job.md) or `capsule replay`) and persists its state, phase,
exit code, duration, and telemetry on the coordinator. This command requires a
configured broker by default. Existing opt-in local records are also readable
without a broker; use `--source local` to select local data explicitly.

```sh
crabbox history
crabbox history --lease cbx_0a1b2c3d4e5f
crabbox history --owner alice@example.com
crabbox history --org example-org --json
crabbox history --state failed --limit 100
```

## Flags

```text
--lease <lease-id>   Filter to runs on a single lease.
--owner <email>      Filter to runs owned by an email.
--org <name>         Filter to runs scoped to an org.
--state <state>      Filter by state: running, succeeded, or failed.
--limit <n>          Maximum runs to return (default 50, broker-capped at 500).
--json               Print the raw run records as JSON.
--source <source>     local, coordinator, or all; configured-broker default is unchanged.
```

## Output

The default output prints one line per run with the run ID, lease ID, lease slug,
state, phase, exit code, duration, start time, an optional resource summary, and
the executed command:

```text
run_a1b2c3d4 cbx_0a1b2c3d4e5f swift-crab succeeded phase=command.finished exit=0 duration=42.1s started=2026-05-29T10:15:04Z resources=load=0.42 mem=38% disk=12% command=npm test
```

Missing values render as `-` (for example a still-running run has no exit code).
The `resources=…` segment appears only when a coordinator-backed Linux run
captured [telemetry](../features/history-logs.md). `--json` emits the full run
records, including the start/end telemetry snapshots, JUnit result summaries, and
classification fields (`blockedStage`, `retryLikely`) when present.

Use a run ID from this list with [`logs`](logs.md), [`events`](events.md), or
[`attach`](attach.md) to inspect a specific run.

## Exporting and importing local records

`history export` and `history import` move private local records between machines
or into archives. Both subcommands accept only `--source local`; exporting never
uploads anything to the coordinator, and importing never contacts it.

```sh
crabbox history export --output runs.tar.gz
crabbox history export run_0123456789abcdef0123456789abcdef --output run.tar.gz
crabbox history export --lease cbx_0a1b2c3d4e5f --state terminal --output closed.tar.gz
crabbox history import runs.tar.gz
crabbox history import - < runs.tar.gz
```

The archive is a streamed gzip tar. `manifest.json` is the first member and
records the schema version, export time, and one entry per run with the record
id, source, start and end times, and the relative paths, sizes, modes, and
SHA-256 digests of `record.json`, `log.txt`, any `results.json`, and the empty
`write.lock`. The original owner-private permissions (`0600` files, `0700`
directories) and the `runs/<id>/…` relative layout are preserved. Only terminal
records are exported; other matched records are skipped with a warning. An
export is refused if any payload contains a ticket, cookie, authorization
header, environment-secret assignment, or private-key marker.

Import verifies the manifest schema and timestamps, every member path (no
absolute paths or `..` traversal), the `0600` modes, and every SHA-256 digest,
then validates the record metadata, log, and results summary against each
other before committing records with atomic directory renames. An existing
record id is rejected by default. `--force` only accepts an existing id when
the current record is terminal and every payload digest already matches the
archive; the record is then left unchanged. After import, `history`, `logs`, and
`results` read the records through the same local paths. Coordinator-sourced
merge behavior is unchanged: a mixed `both` record still coalesces with the
coordinator only when its stored reference matches the configured coordinator.

### Export flags

```text
--output <path>      Archive file (default: standard output); created with mode 0600.
--lease <lease-id>   Filter to runs on a single lease.
--state <state>      Filter by recording state or run status.
--limit <n>          Maximum matched records (0: all).
--json               Print the export summary as JSON.
--source local       Local records only.
```

One or more run ids may be given as positional arguments; they further restrict
the filter. `history import` takes one archive path (`-` for standard input) and
supports `--force` and `--json`.

## Related docs

Local records are created by `run --record-local`, not by reading history.
`history prune --source local` applies the bounded retention policy, and
`history delete <run-id> --source local` removes one inactive local record.
Neither operation stops a lease or changes coordinator records. Active writers
are not pruned. Local source output includes provenance and incomplete status;
see [private local history](../features/history-logs.md#private-local-history).

- [logs](logs.md) — print captured run logs.
- [events](events.md) — print phase and stream events.
- [attach](attach.md) — follow a live run's events.
- [results](results.md) — parsed test-result summaries.
- [History and logs](../features/history-logs.md) — concept overview.
