#!/usr/bin/env bash
#                                          ___
#                                         / _ \
#           ___ _ __  _   _ _ __ ___  _ _| (_) |
#          / _ \ '_ \| | | | '_ ` _ \| '__> _ <
#         |  __/ | | | |_| | | | | | | | | (_) |
#          \___|_| |_|\__,_|_| |_| |_|_|  \___/
#
head $0 -n8|sed -e'1d' -e's/^#//g'
_PIFS=$IFS

DNS="@1.1.1.1"
export DNS

check_tools() {
	tools="sublist3r dig xargs"
	for T in $tools; do
		which $T &>/dev/null
		if [ $? -eq 1 ]; then
			echo "[!] Error: required tool $T not present in PATH"
			exit 1
		fi
	done
}

subdomains() {
	echo "[+] Enumerating subdomains for $1 ..."
	touch $sub_output
	sublist3r -d $1 -o $sub_output &>/dev/null
	sort $sub_output -o $sub_output
}

resolve_sub() {
#	set -x
	record_types="A AAAA CERT CNAME HINFO NS MX PTR SOA SRV TXT URI AXFR"
	sub=$1
	for T in $record_types; do
		IFS=""
		name=$(echo $sub | sed 's/\./-/g')-$T
		res=$(dig $DNS +all +nocmd +noauthority +noqr +nostats $sub $T)
		resp=$(echo $res | awk '/;; ANSWER/,0')
		echo $res | grep "status: NOERROR" &>/dev/null
		if [ $? -eq 0 ]; then
			cnam=$(echo $res | grep 'CNAME')
			if [ $? -eq 0 ] && [ "$T" != "CNAME" ]; then
#				echo "[+] Found CNAME ($sub), skipping"
				continue
			fi
			echo $sub >> $resolved_output;
			if [ -z "$resp" ]; then
#				echo "[+] empty reply for $sub type $T, skipping"
				continue
			fi
			if [ ! -d $base/dns/$T ]; then
				mkdir $base/dns/$T
			fi
			echo $resp > "$base/dns/$T/$name"
		fi
		IFS=$_PIFS
	done
}

get_resolving() {
#	set -x
	echo "[+] Gathering IPs for resolvable subdomains ..."
	export -f resolve_sub
	export resolved_output
	export base
	if [ ! -d "$base/dns" ]; then
		mkdir "$base/dns"
	fi
	touch $resolved_output
	cat "$sub_output" | xargs -I{} bash -c 'resolve_sub {}'
	sort -u $resolved_output -o $resolved_output
}

get_alt_domain() {
#	echo $D:
	echo -e "GET / HTTP/1.0\r\n\r\n" |\
	timeout 5 openssl s_client -connect $D:443 -bugs -ign_eof 2>/dev/null |\
	openssl x509 -text 2>/dev/null |\
	grep DNS
}

find_alt_cert_domains() {
	echo "[+] Searching alternate domains via certificate scan ..."
	touch $alt_domain_output
	for D in $(cat $1); do
		get_alt_domain $1 >> $alt_domain_output
	done
	atmx=`mktemp`
	cat $alt_domain_output | tr ',' '\n' | tr -d ' ' |\
	sort -u | sed 's/^DNS://g' > $atmx
	mv $atmx $alt_domain_output
}

main() {
	# TODO: use spyce api, censys, shodan, crt.sh, whoxy.com

	# enumerate subdomains
	# scan related certificates
	base=`echo $1 | sed 's/\./-/g'`
	if [ -z "$base" ]; then
		echo "Usage: $0 <domain>"
		exit 1
	fi
#	base=`mktemp -d $base.enumr8.XXX`
#	base=""
	check_tools

	if [ -d $base ]; then
		echo "[+] Existing scan folder found: $base"
	else
		mkdir $base
	fi

	sub_output="$base/subdomains"
	if [ -f $sub_output ]; then
		echo "[+] Found subdomain list, will not re-check"
	else
		subdomains $1
	fi

	# find related domains
	alt_domain_output="$base/alt_domains"
	if [ -f $alt_domain_output ]; then
		echo "[+] Found alt domain list, will not re-check"
	else
		find_alt_cert_domains $sub_output
	fi

	# check for fresh domains
	res=$(comm $base/alt_domains $base/subdomains -2 -3)
	if [ ! -z "$res" ]; then
		echo "[+] New domains: (go rerun the tool on these)"
		IFS=""
		echo $res
		IFS=$_PIFS
	fi

	# check list of alt domains on SSL cert on port 443
	# possibly loop back to subdomain enumeration for new domains

	resolved_output="$base/resolved"
	get_resolving $sub_output
}

main $*
