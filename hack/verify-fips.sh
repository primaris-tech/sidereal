#!/usr/bin/env bash
# verify-fips.sh - Verify FIPS 140-2 validated cryptography in Sidereal binaries
#
# Usage:
#   ./hack/verify-fips.sh                    # Verify all Go binaries in bin/
#   ./hack/verify-fips.sh bin/controller     # Verify a specific binary
#   ./hack/verify-fips.sh --docker           # Verify Docker images
#
# Go binaries: checks for BoringCrypto symbols (CMVP #3678)
# Rust binary: built with aws-lc-rs FIPS feature (CMVP #4816), verified at build time

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

PASS=0
FAIL=0

verify_go_binary() {
    local binary="$1"
    local name
    name=$(basename "$binary")

    if [[ ! -f "$binary" ]]; then
        echo -e "${RED}FAIL${NC}: $binary not found"
        FAIL=$((FAIL + 1))
        return
    fi

    if go tool nm "$binary" 2>/dev/null | grep -qE '_Cfunc__goboringcrypto_|crypto/internal/boring'; then
        echo -e "${GREEN}PASS${NC}: $name - BoringCrypto symbols present"
        PASS=$((PASS + 1))
    else
        echo -e "${RED}FAIL${NC}: $name - BoringCrypto symbols NOT found"
        echo "       Binary may not have been built with GOEXPERIMENT=boringcrypto"
        FAIL=$((FAIL + 1))
    fi
}

verify_docker_image() {
    local image="$1"
    local label_value

    label_value=$(docker inspect --format='{{index .Config.Labels "io.sidereal.fips"}}' "$image" 2>/dev/null || echo "")

    if [[ -z "$label_value" ]]; then
        echo -e "${RED}FAIL${NC}: $image - missing io.sidereal.fips label"
        FAIL=$((FAIL + 1))
        return
    fi

    echo -e "${GREEN}PASS${NC}: $image - FIPS label: $label_value"
    PASS=$((PASS + 1))
}

echo "Sidereal FIPS Verification"
echo "=========================="
echo ""

if [[ "${1:-}" == "--docker" ]]; then
    echo "Verifying Docker images..."
    echo ""

    IMAGES=(
        "ghcr.io/primaris-tech/sidereal-controller:latest"
        "ghcr.io/primaris-tech/sidereal-probe-go:latest"
        "ghcr.io/primaris-tech/sidereal-probe-detection:latest"
        "ghcr.io/primaris-tech/sidereal-probe-bootstrap:latest"
    )

    for img in "${IMAGES[@]}"; do
        if docker image inspect "$img" &>/dev/null; then
            verify_docker_image "$img"
        else
            echo -e "${YELLOW}SKIP${NC}: $img - image not found locally"
        fi
    done
elif [[ $# -gt 0 ]]; then
    # Verify specific binary
    for binary in "$@"; do
        verify_go_binary "$binary"
    done
else
    # Verify all Go binaries in bin/
    echo "Verifying Go binaries (BoringCrypto CMVP #3678)..."
    echo ""

    GO_BINARIES=(
        "bin/controller"
        "bin/probe-rbac"
        "bin/probe-netpol"
        "bin/probe-admission"
        "bin/probe-secret"
        "bin/probe-bootstrap"
        "bin/sidereal"
    )

    for binary in "${GO_BINARIES[@]}"; do
        verify_go_binary "$binary"
    done
fi

echo ""
echo "=========================="
echo -e "Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}"

if [[ $FAIL -gt 0 ]]; then
    exit 1
fi
