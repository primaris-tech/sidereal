#!/usr/bin/env bash
# hack/bootstrap-kind.sh — Stand up a local Sidereal development environment on KIND.
#
# Creates a KIND cluster, installs Kyverno, builds and loads Sidereal images,
# installs Sidereal via Helm, and runs a first RBAC probe to verify the stack.
#
# Usage:
#   ./hack/bootstrap-kind.sh [flags]
#
# Flags:
#   --cluster-name NAME    KIND cluster name (default: sidereal-dev)
#   --skip-build           Skip make docker-build-all; use images already in Docker
#   --teardown             Delete the KIND cluster and all associated resources
#   --help                 Show this message

set -euo pipefail

# ---------------------------------------------------------------------------
# Config / defaults
# ---------------------------------------------------------------------------

CLUSTER_NAME="sidereal-dev"
SKIP_BUILD=false
TEARDOWN=false

REGISTRY="ghcr.io/primaris-tech"
IMAGE_TAG="latest"

KYVERNO_CHART_VERSION="3.3.4"   # Kyverno app v1.13.x
SIDEREAL_NAMESPACE="sidereal-system"
DEMO_NAMESPACE="sidereal-demo"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }
step()    { echo -e "\n${BOLD}==> $*${NC}"; }

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

while [[ $# -gt 0 ]]; do
  case "$1" in
    --cluster-name)
      CLUSTER_NAME="$2"; shift 2 ;;
    --skip-build)
      SKIP_BUILD=true; shift ;;
    --teardown)
      TEARDOWN=true; shift ;;
    --help|-h)
      sed -n '/^# Usage:/,/^$/p' "${BASH_SOURCE[0]}" | grep -v '^#$' | sed 's/^#[[:space:]]*//'
      exit 0 ;;
    *)
      error "Unknown flag: $1. Run with --help for usage." ;;
  esac
done

# ---------------------------------------------------------------------------
# Teardown path
# ---------------------------------------------------------------------------

if [[ "${TEARDOWN}" == "true" ]]; then
  step "Tearing down cluster: ${CLUSTER_NAME}"
  if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
    kind delete cluster --name "${CLUSTER_NAME}"
    success "Cluster deleted."
  else
    warn "Cluster '${CLUSTER_NAME}' not found — nothing to delete."
  fi
  exit 0
fi

# ---------------------------------------------------------------------------
# Prerequisite checks
# ---------------------------------------------------------------------------

step "Checking prerequisites"

check_prereq() {
  local cmd="$1"
  local hint="${2:-}"
  if ! command -v "${cmd}" &>/dev/null; then
    error "'${cmd}' not found.${hint:+ ${hint}}"
  fi
  success "${cmd}"
}

check_prereq kind    "Install from https://kind.sigs.k8s.io/docs/user/quick-start/#installation"
check_prereq kubectl "Install from https://kubernetes.io/docs/tasks/tools/"
check_prereq helm    "Install from https://helm.sh/docs/intro/install/"
check_prereq docker  "Install from https://docs.docker.com/get-docker/"

if [[ "${SKIP_BUILD}" == "false" ]]; then
  check_prereq make "Install build-essential (Linux) or Xcode CLT (macOS)"
fi

# ---------------------------------------------------------------------------
# Images the Helm chart requires
# ---------------------------------------------------------------------------

IMAGES=(
  "${REGISTRY}/sidereal-controller:${IMAGE_TAG}"
  "${REGISTRY}/sidereal-probe-go:${IMAGE_TAG}"
  "${REGISTRY}/sidereal-probe-detection:${IMAGE_TAG}"
  "${REGISTRY}/sidereal-probe-bootstrap:${IMAGE_TAG}"
)

# ---------------------------------------------------------------------------
# Step 1: KIND cluster
# ---------------------------------------------------------------------------

step "Creating KIND cluster: ${CLUSTER_NAME}"

if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
  warn "Cluster '${CLUSTER_NAME}' already exists — skipping creation."
else
  kind create cluster \
    --name "${CLUSTER_NAME}" \
    --config "${SCRIPT_DIR}/kind-config.yaml" \
    --wait 60s
  success "Cluster created."
fi

# Point kubectl at the new cluster.
kubectl config use-context "kind-${CLUSTER_NAME}" >/dev/null
success "kubectl context: kind-${CLUSTER_NAME}"

# ---------------------------------------------------------------------------
# Step 2: Kyverno
# ---------------------------------------------------------------------------

step "Installing Kyverno ${KYVERNO_CHART_VERSION}"

helm repo add kyverno https://kyverno.github.io/kyverno/ --force-update >/dev/null

if helm status kyverno -n kyverno &>/dev/null; then
  warn "Kyverno already installed — skipping."
else
  helm install kyverno kyverno/kyverno \
    --namespace kyverno \
    --create-namespace \
    --version "${KYVERNO_CHART_VERSION}" \
    --set admissionController.replicas=1 \
    --set backgroundController.enabled=false \
    --set cleanupController.enabled=false \
    --set reportsController.enabled=false \
    --wait \
    --timeout 5m
  success "Kyverno installed."
fi

info "Waiting for Kyverno admission controller to be ready..."
kubectl rollout status deployment/kyverno-admission-controller \
  -n kyverno --timeout=120s
success "Kyverno ready."

# ---------------------------------------------------------------------------
# Step 3: Build and load Sidereal images
# ---------------------------------------------------------------------------

step "Preparing Sidereal images"

if [[ "${SKIP_BUILD}" == "false" ]]; then
  info "Building all Sidereal images (this takes a few minutes)..."
  cd "${REPO_ROOT}"
  make docker-build-all
  success "Images built."
else
  warn "--skip-build set; assuming images are already present in Docker."
fi

info "Loading images into KIND cluster..."
for img in "${IMAGES[@]}"; do
  # Skip the detection image in dev — it requires FIPS Rust build toolchain.
  if [[ "${img}" == *"probe-detection"* ]]; then
    warn "Skipping detection probe image (requires Rust FIPS build); set profile.detectionBackend=none."
    continue
  fi
  if docker image inspect "${img}" &>/dev/null; then
    kind load docker-image "${img}" --name "${CLUSTER_NAME}"
    success "Loaded: ${img}"
  else
    warn "Image not found locally, skipping: ${img}"
  fi
done

# ---------------------------------------------------------------------------
# Step 4: Install Sidereal
# ---------------------------------------------------------------------------

step "Installing Sidereal"

HELM_ARGS=(
  "--namespace" "${SIDEREAL_NAMESPACE}"
  "--create-namespace"
  # Impact level: low cascades 24h cadence, 180d retention, no fail-closed.
  "--set" "global.impactLevel=low"
  # Start in observe mode: probe Jobs run and results are recorded, but no
  # incidents are created. Safe for dev and first-time evaluation.
  "--set" "global.executionMode=observe"
  # Disable FIPS-validated crypto for local dev (no BoringCrypto build required).
  "--set" "global.fips=false"
  # Kyverno is installed — enable admission controller requirement.
  "--set" "global.requireAdmissionController=true"
  # Profile: Kyverno admission, no detection backend, tcp-inference CNI.
  "--set" "profile.admissionController=kyverno"
  "--set" "profile.signatureVerifier=kyverno"
  "--set" "profile.detectionBackend=none"
  "--set" "profile.cniObservability=tcp-inference"
  # Disable TLS requirement for local dev.
  "--set" "tls.required=false"
  # Image tags and pull policy for locally-loaded images.
  "--set" "controller.image.tag=${IMAGE_TAG}"
  "--set" "controller.image.pullPolicy=Never"
  "--set" "probe.goImage.tag=${IMAGE_TAG}"
  "--set" "probe.goImage.pullPolicy=Never"
  "--set" "probe.bootstrapImage.tag=${IMAGE_TAG}"
  "--set" "probe.bootstrapImage.pullPolicy=Never"
  # No detection probes in this profile.
  "--set" "probe.detectionImage.tag=${IMAGE_TAG}"
)

if helm status sidereal -n "${SIDEREAL_NAMESPACE}" &>/dev/null; then
  warn "Sidereal already installed — running helm upgrade."
  helm upgrade sidereal "${REPO_ROOT}/deploy/helm/sidereal/" "${HELM_ARGS[@]}" --wait --timeout 3m
else
  helm install sidereal "${REPO_ROOT}/deploy/helm/sidereal/" "${HELM_ARGS[@]}" --wait --timeout 3m
fi

success "Sidereal installed."

# ---------------------------------------------------------------------------
# Step 5: Verify installation
# ---------------------------------------------------------------------------

step "Verifying installation"

kubectl rollout status deployment/sidereal-controller-manager \
  -n "${SIDEREAL_NAMESPACE}" --timeout=120s
success "Controller manager ready."

echo ""
kubectl get pods -n "${SIDEREAL_NAMESPACE}"

ALERT_COUNT=$(kubectl get siderealsystemalerts -n "${SIDEREAL_NAMESPACE}" \
  --no-headers 2>/dev/null | wc -l | tr -d ' ')
if [[ "${ALERT_COUNT}" -gt 0 ]]; then
  warn "${ALERT_COUNT} SiderealSystemAlert(s) present — probes may be blocked."
  kubectl get siderealsystemalerts -n "${SIDEREAL_NAMESPACE}"
fi

# ---------------------------------------------------------------------------
# Step 6: Create demo namespace and run first probe
# ---------------------------------------------------------------------------

step "Running first RBAC probe"

kubectl create namespace "${DEMO_NAMESPACE}" --dry-run=client -o yaml \
  | kubectl apply -f -

info "Applying RBAC probe to namespace '${DEMO_NAMESPACE}'..."
kubectl apply -f - <<EOF
apiVersion: sidereal.cloud/v1alpha1
kind: SiderealProbe
metadata:
  name: rbac-getting-started
  namespace: ${SIDEREAL_NAMESPACE}
spec:
  probeType: rbac
  targetNamespace: ${DEMO_NAMESPACE}
  executionMode: observe
  intervalSeconds: 300
  controlMappings:
    nist-800-53:
      - AC-6
      - AC-6(5)
EOF
success "Probe applied."

# ---------------------------------------------------------------------------
# Step 7: Wait for first result
# ---------------------------------------------------------------------------

step "Waiting for first probe result (up to 90s)"

RESULT_FOUND=false
for i in $(seq 1 18); do
  RESULT=$(kubectl get siderealproberesults -n "${SIDEREAL_NAMESPACE}" \
    -l "sidereal.cloud/probe-name=rbac-getting-started" \
    --no-headers 2>/dev/null | head -1)
  if [[ -n "${RESULT}" ]]; then
    RESULT_FOUND=true
    break
  fi
  info "Waiting... (${i}/18)"
  sleep 5
done

echo ""

if [[ "${RESULT_FOUND}" == "true" ]]; then
  success "First probe result received."
  echo ""
  kubectl get siderealproberesults -n "${SIDEREAL_NAMESPACE}" \
    -l "sidereal.cloud/probe-name=rbac-getting-started" \
    -o custom-columns=\
"NAME:.metadata.name,\
OUTCOME:.spec.outcome,\
EFFECTIVENESS:.spec.controlEffectiveness,\
INTEGRITY:.spec.integrityStatus,\
AGE:.metadata.creationTimestamp"
  echo ""
  info "Full result details:"
  kubectl describe siderealproberesult -n "${SIDEREAL_NAMESPACE}" \
    -l "sidereal.cloud/probe-name=rbac-getting-started" \
    | grep -A 50 "^Spec:" || true
else
  warn "No result yet — the probe Job may still be running."
  info "Check status with:"
  info "  kubectl get jobs -n ${SIDEREAL_NAMESPACE} -l sidereal.cloud/probe-name=rbac-getting-started"
  info "  kubectl get siderealproberesults -n ${SIDEREAL_NAMESPACE} --watch"
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

echo ""
echo -e "${GREEN}${BOLD}Bootstrap complete.${NC}"
echo ""
echo -e "${BOLD}Cluster:${NC}     kind-${CLUSTER_NAME}"
echo -e "${BOLD}Namespace:${NC}   ${SIDEREAL_NAMESPACE}"
echo -e "${BOLD}Demo target:${NC} ${DEMO_NAMESPACE}"
echo ""
echo -e "${BOLD}Useful commands:${NC}"
echo "  kubectl get siderealprobes -n ${SIDEREAL_NAMESPACE}"
echo "  kubectl get siderealproberesults -n ${SIDEREAL_NAMESPACE} --watch"
echo "  kubectl get siderealproberecommendations -n ${SIDEREAL_NAMESPACE}"
echo "  kubectl get siderealsystemalerts -n ${SIDEREAL_NAMESPACE}"
echo ""
echo -e "${BOLD}Teardown:${NC}"
echo "  ./hack/bootstrap-kind.sh --teardown --cluster-name ${CLUSTER_NAME}"
echo ""
