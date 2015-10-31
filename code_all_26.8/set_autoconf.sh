sysctl -w net.ipv6.conf.all.autoconf=1
sysctl -w net.ipv6.conf.default.autoconf=1
sysctl -w net.ipv6.conf.all.accept_ra=1
sysctl -w net.ipv6.conf.default.accept_ra=1
sysctl -w net.ipv6.conf.all.forwarding=1
sysctl -w net.ipv6.conf.default.forwarding=1
