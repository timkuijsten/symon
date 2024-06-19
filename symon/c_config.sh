#!/bin/sh
#
# Create an example configuration file for symon on a host and print to stdout

# exit on errors, use a sane path and install prefix
#
set -e
PATH=/bin:/usr/bin:/sbin:/usr/sbin
OS=`uname -s`
# verify proper execution
#
if [ $# -ge 3 ]; then
    echo "usage: $0 [host] [port]" >&2
    exit 1
fi
case "${OS}" in
OpenBSD)
	interfaces=`netstat -ni | sed '1,1d;s/^\([a-z]*[0-9]\).*$/\1/g' | uniq`
	io=`mount | sed -n '/^\/dev/ s@/dev/\([a-z]*[0-9]\).*@io(\1), @p' | sort -u | tr -d \\\n`
        cpu="cpu(0),"
	;;
FreeBSD|NetBSD)
	interfaces=`ifconfig -l`
	io=`mount | sed -n '/^\/dev/ s@/dev/\([a-z]*[0-9]\).*@io(\1), @p' | sort -u | tr -d \\\n`
        cpu=`sysctl dev.cpu | grep '%desc' | sed -n 's/dev.cpu.\([0-9]*\).*$/cpu(\1), /p'`
	;;
Linux)
	interfaces=`ifconfig -a| sed -n '/^[a-z]/ s,\([a-z]*[0-9]\).*,\1,p' | sort -u`
	io=`mount | sed -n '/^\/dev/ s@/dev/\([a-z]*[0-9]\).*@io(\1), @p;s@/dev/\(x[a-z]\+[0-9]*\).*@io(\1), @p' | sort -u | tr -d \\\n`
        cpu=`cat /proc/cpuinfo | sed -n '/^processor/ s@[^:]\+: \([0-9]\+\)@cpuiow\(\1\), @p' | sort -u | tr -d \\\n`
	;;
esac;
for i in $interfaces; do
case $i in
bridge*|carp*|enc*|gif*|gre*|lo*|pflog*|pfsync*|ppp*|sl*|tun*|vlan*)
	# ignore this interface
	;;
*)
	if="if($i), $if"
	;;
esac
done
host=${1:-127.0.0.1}
port=${2:-2100}
cat <<EOF
#
# symon configuration generated by
# `basename $0` $1 $2
#
monitor { ${if}${io}${cpu}mem } stream to $host $port
EOF