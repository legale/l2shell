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
Start a server on a machine 1.
```sh
./a eth1 bash
```
This will start an l2shell server with bash as cli

### client
Start a client on a machine 2.
```sh
./b eth1 11:22:33:44:55:66
```
This will connect client to the server machine with mac `11:22:33:44:55:66`

By default the client disables local echo for a clean remote shell. Append `--local-echo` if you explicitly need to see your keystrokes locally.

## тестирование
Юнит-тесты для общих хелперов (CRC, упаковка кадров, дедупликация) живут в `tests/` и используют легковесный раннер из корневого `test_util.h`, поэтому никаких внешних библиотек не требуется. В консоли появятся строки вида `error: payload size too large` и `error: crc mismatch` — это часть негативных сценариев, а не фейлы:

```sh
make test-unit
```
