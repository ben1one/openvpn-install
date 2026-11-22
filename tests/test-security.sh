#!/usr/bin/env bash
# Run the portable checks and the Ubuntu compatibility checks in Docker.
set -euo pipefail

project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
bash -n "$project_dir/openvpn-install.sh"
echo 'PASS: installer Bash syntax'

if ! command -v docker >/dev/null 2>&1; then
	echo 'Docker is required for the Ubuntu checks.' >&2
	exit 1
fi

docker run --rm -v "$project_dir:/project:ro" ubuntu:22.04 \
	bash /project/tests/test-security-ubuntu.sh
