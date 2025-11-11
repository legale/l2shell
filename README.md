# l2shell
layer 2 based shell client/server

## compile
```sh
git clone https://github.com/legale/l2shell
cd l2shell
make
```

- `a` bin is a server
- `b` bin is a client

## usage
### server
Start a server on machine 1 (no command argument needed).
```sh
./a eth1
```
The server waits for the first client frame, reads the requested command from its payload, and launches it (defaults to `/bin/sh` if the client keeps the default).

### client
Start a client on a machine 2.
```sh
./b eth1 11:22:33:44:55:66 /bin/bash
```
This connects the client to the server machine with MAC `11:22:33:44:55:66` and asks it to spawn `/bin/bash` as the interactive shell.

By default the client disables local echo for a clean remote shell. Append `--local-echo` if you explicitly need to see your keystrokes locally.

To send a one-off command after the session is up (and exit once the response arrives):
```sh
./b eth1 11:22:33:44:55:66 /bin/bash "echo 123"
```
The client first establishes the remote shell (`/bin/bash`), pushes the command followed by a newline, prints the remote output, and exits once the response arrives (used by the bridge test harness).

## тестирование
Юнит-тесты для общих хелперов (CRC, упаковка кадров, дедупликация) живут в `tests/` и используют легковесный раннер из корневого `test_util.h`, поэтому никаких внешних библиотек не требуется. В консоли появятся строки вида `error: payload size too large` и `error: crc mismatch` — это часть негативных сценариев, а не фейлы:

```sh
make test-unit
```
