#!/bin/sh

gcc -ggdb -Wl,-z,relro,-z,now -fstack-protector-strong -Wformat -Werror=format-security -D_FORTIFY_SOURCE=2 csamp.c -lpcap -o ../bin/csamp
