#!/usr/bin/env bash
# Invoked in a disposable Ubuntu container by test-security.sh.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends systemd openvpn >/tmp/test-install.log 2>&1 || {
	cat /tmp/test-install.log >&2
	exit 1
}

installer=/project/openvpn-install.sh
dropin=/etc/systemd/system/openvpn-server@server.service.d/openvpn-install-hardening.conf
mkdir -p "$(dirname "$dropin")" /var/lib/openvpn-install
awk '/cat > .*openvpn-install-hardening.conf <<.EOF./ {copy=1; next}
     copy && /^EOF$/ {exit} copy {print}' "$installer" > "$dropin"
for setting in '[Service]' 'ProtectSystem=strict' 'ReadWritePaths=/var/lib/openvpn-install' 'NoNewPrivileges=true' 'PrivateTmp=true'; do
	grep -Fxq "$setting" "$dropin" || { echo "Missing sandbox setting: $setting" >&2; exit 1; }
done
if ! systemd-analyze verify openvpn-server@server.service >/tmp/test-systemd.log 2>&1; then
	cat /tmp/test-systemd.log >&2
	exit 1
fi
echo 'PASS: systemd service and sandbox configuration accepted'

for cipher in AES-256-GCM AES-128-GCM; do
	openvpn --show-ciphers | grep -q "$cipher" || { echo "Missing cipher: $cipher" >&2; exit 1; }
done
[[ $(grep -Fc 'data-ciphers AES-256-GCM:AES-128-GCM' "$installer") -eq 2 ]]
[[ $(grep -Fc 'tls-version-min 1.2' "$installer") -eq 2 ]]
echo 'PASS: OpenVPN supports configured ciphers; server and client specify TLS settings'

test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT
awk '/^build_client\(\) \{/{copy=1} copy{print} copy && /^\}/{exit}' "$installer" > "$test_dir/function.sh"
cat > "$test_dir/easyrsa" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" > "$TEST_ARGS"
EOF
chmod +x "$test_dir/easyrsa"
cd "$test_dir"
export TEST_ARGS="$test_dir/args"
client=alice
source ./function.sh
printf 'y\n' | build_client
[[ $(cat "$TEST_ARGS") == '--batch --days=3650 build-client-full alice' ]]
printf 'n\n' | build_client
[[ $(cat "$TEST_ARGS") == '--batch --days=3650 build-client-full alice nopass' ]]
printf 'invalid\ny\n' | build_client
[[ $(cat "$TEST_ARGS") == '--batch --days=3650 build-client-full alice' ]]
if build_client </dev/null; then
	echo 'Unexpected success when input closes' >&2
	exit 1
fi
echo 'PASS: client passphrase selection, invalid input, and EOF (mock Easy-RSA)'

awk '/^cidr_to_route\(\) \{/{copy=1} copy{print} copy && /^\}/{exit}' "$installer" > "$test_dir/routes.sh"
source "$test_dir/routes.sh"
[[ $(cidr_to_route 192.168.10.0/24) == 'push "route 192.168.10.0 255.255.255.0"' ]]
[[ $(cidr_to_route 10.0.0.0/8) == 'push "route 10.0.0.0 255.0.0.0"' ]]
[[ $(cidr_to_route 192.0.2.1/32) == 'push "route 192.0.2.1 255.255.255.255"' ]]
for bad in 192.168.10.1/24 256.0.0.0/8 0.0.0.0/0 10.0.0.0/33 bad; do
	if cidr_to_route "$bad" >/dev/null; then
		echo "Invalid network accepted: $bad" >&2
		exit 1
	fi
done
echo 'PASS: split-tunnel routes and invalid networks'

mkdir -p /etc/openvpn/server/easy-rsa/pki/inline/private
printf 'V\t301231000000Z\t\t01\tunknown\t/CN=server\nV\t301231000000Z\t\t02\tunknown\t/CN=alice\nR\t301231000000Z\t\t03\tunknown\t/CN=revoked\n' > /etc/openvpn/server/easy-rsa/pki/index.txt
printf 'client\n' > /etc/openvpn/server/client-common.txt
printf '<key>\ntest-key\n</key>\n' > /etc/openvpn/server/easy-rsa/pki/inline/private/alice.inline
for name in select_client export_client; do
	awk -v start="$name() {" '$0 == start {copy=1} copy {print} copy && /^\}/ {exit}' "$installer" > "$test_dir/$name.sh"
	source "$test_dir/$name.sh"
done
select_client <<<'1'
[[ "$client" == alice ]]
script_dir="$test_dir"
export_client <<<''
grep -Fxq 'test-key' "$test_dir/alice.ovpn"
[[ $(stat -c '%a' "$test_dir/alice.ovpn") == 600 ]]
if export_client <<<''; then
	echo 'Export unexpectedly overwrote an existing file' >&2
	exit 1
fi
if select_client <<<'2'; then
	echo 'Selected a revoked or nonexistent client' >&2
	exit 1
fi
echo 'PASS: client selection, secure export, and overwrite protection'
