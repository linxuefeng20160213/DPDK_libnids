cmd_killtcp.o = gcc -Wp,-MD,./.killtcp.o.d.tmp -g -O0 -D_BSD_SOURCE -DLIBNET_VER=1 -DHAVE_ICMPHDR=1 -DHAVE_TCP_STATES=1 -DHAVE_BSD_UDPHDR=1   -o killtcp.o -c /home/vvarghes/Projects/dpdk-2.2.0/examples/libnids/libnids-1.24/src/killtcp.c 