cmd_/home/ru/l2shell/l2shell/src/l2shell_kmod.mod := printf '%s\n'   l2shell_kmod.o | awk '!x[$$0]++ { print("/home/ru/l2shell/l2shell/src/"$$0) }' > /home/ru/l2shell/l2shell/src/l2shell_kmod.mod
