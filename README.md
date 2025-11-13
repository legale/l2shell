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
Start a server on machine 1.
```sh
./a eth1
```

### client
Start a client on a machine 2.
```sh
./b eth1 11:22:33:44:55:66 /bin/bash
```

The client ask server to run /bin/bash
