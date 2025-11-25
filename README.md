# l2shell
Layer-2 shell client/server pair that connects hosts using only raw Ethernet frames (custom EtherType `0x88B5`), so both sides can talk even without configured IP stacks—useful for emergency recovery when L3 settings are missing or broken.

## Build
You need a POSIX toolchain on Linux with `make` and a C compiler. Clone the repo and run:

```sh
git clone https://github.com/legale/l2shell
cd l2shell/src
make
```

The build produces:
- `l2shell`: stripped release binary (acts as server or client depending on argv).
- `l2shell_dbg`: debug build with symbols.
- `l2shell_static`: fully static variant.
- `a` / `b`: convenience symlinks that force server/client mode.

Run `make test-unit` for the unit tests or `make test` (requires `sudo`) for the end-to-end veth test harness. `make kmod` builds the optional kernel helper (`l2shell_kmod.ko`); make sure kernel headers for the running kernel are installed before compiling it.

## Usage
`l2shell` is a single binary with two subcommands. You can call it via `./l2shell server ...`, `./l2shell client ...`, or through the `./a` (`server`) and `./b` (`client`) symlinks. Raw Ethernet access usually requires root privileges.

### Typical session
1. Start the server and allow it to accept packets on any interface, automatically replying on the interface that delivered the frame:
   ```sh
   sudo ./l2shell server any
   ```
2. From the client host, point at the interface that faces the server and its MAC:
   ```sh
   sudo ./l2shell client <ifname> <server_mac>
   ```
   After the HELLO handshake completes, the server spawns `login` (default) unless you override it in the client CLI.

### Server
```
./l2shell server [--log-file <path>] <interface|any>
```
- `<interface>` is the NIC to bind to (for example `eth0`).
- `any` switches the server into a promiscuous mode where it listens on all interfaces and responds out of the interface that saw the client frame.
- `--log-file` redirects stdout/stderr to a file (logs use `param=value` format).

The server waits for a HELLO packet from the client. If the client asked for a specific shell (e.g. `/bin/sh`), that command is executed inside a PTY; otherwise `/bin/login` is used. Lack of client activity for the negotiated idle timeout (default 30 s, capped at 600 s) terminates the shell.

### Client
```
./l2shell client [options] <iface> <server-mac> [shell] [cmd]
```
Required arguments:
- `<iface>`: interface used to send Ethernet frames (must be on the same L2 domain as the server).
- `<server-mac>`: destination MAC address (`aa:bb:cc:dd:ee:ff` format).

Optional positional arguments:
- `shell`: command to ask the server to run instead of the default `login`.
- `cmd`: one-shot command sent after HELLO. If omitted, the client becomes interactive and forwards stdin/stdout until you exit.

Useful flags:
- `-e`, `--echo`: also print what you type locally (handy when stdin is not a TTY).
- `--spawn <path>`: request that the kernel helper launches this server binary (for setups where the kernel module autostarts `l2shell`).
- `--idle-timeout <sec>`: suggest an idle timeout (1-600 s).
- `--log-file <path>`: redirect client logs to a file.
- `-h`, `--help`: print the CLI synopsis.

When `cmd` is provided, the client sends it once (appending CR/LF), waits for a response, and exits. Without `cmd`, stdin is placed into raw mode, and the tool acts as a transparent PTY with optional local echo.

## Repository layout
- `src/`: portable userland code, tests, scripts, and Makefile (build everything from here).
- `openwrt/`: OpenWrt packaging files.
- `logs/`: default log output location.
- `map.md`: project roadmap and coding standards; read it before making changes.
