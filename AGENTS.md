# Repository Guidelines

## Project Structure & Module Organization
Runtime sources live at the repo root: `server.c` builds the `a` binary (server), `client.c` builds `b` (client), and `common.c/h` hold shared packet helpers. Static variants (`a_static`, `b_static`) are emitted alongside the dynamic bins for constrained hosts. Support assets sit under `scripts/` (automation and tests) and `test_logs/` (artifacts from local runs).

## Build, Test, and Development Commands
- `make` — compiles `a`, `b`, and their `_static` counterparts using the flags in `Makefile`.
- `make clean` — removes objects, binaries, and intermediates; run before benchmarking size-sensitive changes.
- `sudo make test` — executes `scripts/test_local.sh`, creating a `veth` pair and logging to `test_logs/server.log` and `test_logs/client.log`.

## Coding Style & Naming Conventions
C sources use 4-space indentation, brace-on-same-line functions, and lowercase_with_underscores for functions (`handle_client_read`) and globals (`sh_fd`). Shared constants live in `common.h`; prefer `static inline` helpers there instead of new macros. Keep comments concise and English-first, and match the existing error-handling pattern of early returns plus `perror` context.

## Testing Guidelines
The `scripts/test_local.sh` harness spins up `veth_srv0`/`veth_cli0`, feeds a `ping_over_l2shell` payload through `/bin/cat`, and checks the client log. Because it toggles interfaces, it must run as root (see the `sudo make test` wrapper). Add lightweight probes by extending the script with additional payload asserts and log checks; store artifacts under `test_logs/` so `make clean` can safely ignore them.

## Commit & Pull Request Guidelines
History is minimal and uses short summaries (“first commit”, “Initial commit”), so keep subject lines under ~50 characters, written in present tense (e.g., “Add MAC filter validation”). Provide context in the body for protocol changes: why the change is needed, how it was tested (include `sudo make test` output or log excerpts), and any operator actions required. PRs should link the motivating issue, enumerate interface or command changes, and note impacts on `a` vs `b`.

## Security & Configuration Tips
Never hard-code production MAC addresses in sources; pass them as CLI args like `./b eth1 11:22:33:44:55:66`. When testing new interfaces, reset them via `ip link del <ifname>` to avoid leaking stale veth pairs. Keep private keys or deployment credentials outside the repo—only the sample `scp` lines in the `Makefile` should reference remote hosts.
