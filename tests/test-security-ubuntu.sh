#!/usr/bin/env bash
# Invoked in a disposable Ubuntu container by test-security.sh.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends systemd openvpn openssl python3 >/tmp/test-install.log 2>&1 || {
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
for name in read_certificate_days warn_ca_expiry build_client; do
	awk -v start="$name() {" '$0 == start {copy=1} copy {print} copy && /^\}/ {exit}' "$installer" >> "$test_dir/function.sh"
done
cat > "$test_dir/easyrsa" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" > "$TEST_ARGS"
EOF
chmod +x "$test_dir/easyrsa"
cd "$test_dir"
export TEST_ARGS="$test_dir/args"
client=alice
source ./function.sh
printf '\ny\n' | build_client
[[ $(cat "$TEST_ARGS") == '--batch --days=3650 build-client-full alice' ]]
printf '\nn\n' | build_client
[[ $(cat "$TEST_ARGS") == '--batch --days=3650 build-client-full alice nopass' ]]
printf '0\n730\ninvalid\ny\n' | build_client
[[ $(cat "$TEST_ARGS") == '--batch --days=730 build-client-full alice' ]]
if build_client </dev/null; then
	echo 'Unexpected success when input closes' >&2
	exit 1
fi
echo 'PASS: client passphrase selection, invalid input, and EOF (mock Easy-RSA)'
openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=test-ca -days 1 \
	-keyout "$test_dir/ca.key" -out "$test_dir/ca.crt" >/dev/null 2>&1
certificate_days=2
[[ $(warn_ca_expiry "$test_dir/ca.crt") == *'Warning: the CA expires'* ]]
echo 'PASS: warning when requested lifetime exceeds CA validity'

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

printf 'port 1194\n' > /etc/openvpn/server/server.conf
for name in backup_server extract_server_backup; do
	awk -v start="$name() {" '$0 == start {copy=1} copy {print} copy && /^\}/ {exit}' "$installer" > "$test_dir/$name.sh"
	source "$test_dir/$name.sh"
done
backup_server <<<''
[[ $(stat -c '%a' "$test_dir/openvpn-backup.tar.gz") == 600 ]]
mkdir "$test_dir/restore"
extract_server_backup "$test_dir/openvpn-backup.tar.gz" "$test_dir/restore"
cmp /etc/openvpn/server/server.conf "$test_dir/restore/server/server.conf"
python3 - "$test_dir/unsafe.tar.gz" <<'PY'
import io, sys, tarfile
with tarfile.open(sys.argv[1], 'w:gz') as archive:
    for name in ('server/server.conf', 'server/../../escape'):
        info = tarfile.TarInfo(name)
        info.size = 1
        archive.addfile(info, io.BytesIO(b'x'))
PY
if extract_server_backup "$test_dir/unsafe.tar.gz" "$test_dir/restore"; then
	echo 'Unsafe archive unexpectedly accepted' >&2
	exit 1
fi
echo 'PASS: private backup, safe extraction, and archive traversal rejection'

awk -v start='restore_server() {' '$0 == start {copy=1} copy {print} copy && /^\}/ {exit}' "$installer" > "$test_dir/restore_server.sh"
source "$test_dir/restore_server.sh"
cat > "$test_dir/systemctl" <<'EOF'
#!/usr/bin/env bash
if [[ "$1" == start && -e "$FAIL_ONCE" ]]; then
	rm -f "$FAIL_ONCE"
	exit 1
fi
exit 0
EOF
chmod +x "$test_dir/systemctl"
export PATH="$test_dir:$PATH" FAIL_ONCE="$test_dir/fail-once"
group_name=nogroup
printf 'port 443\n' > /etc/openvpn/server/server.conf
printf '%s\nRESTORE\n' "$test_dir/openvpn-backup.tar.gz" | restore_server
grep -Fxq 'port 1194' /etc/openvpn/server/server.conf
printf 'port 443\n' > /etc/openvpn/server/server.conf
touch "$FAIL_ONCE"
if printf '%s\nRESTORE\n' "$test_dir/openvpn-backup.tar.gz" | restore_server; then
	echo 'Restore unexpectedly succeeded after a simulated service failure' >&2
	exit 1
fi
grep -Fxq 'port 443' /etc/openvpn/server/server.conf
echo 'PASS: restore and rollback after simulated service failure'
