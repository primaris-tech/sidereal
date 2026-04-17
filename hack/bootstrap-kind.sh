#!/usr/bin/env bash
# hack/bootstrap-kind.sh — Stand up a local Sidereal development environment on KIND.
#
# Creates a KIND cluster, installs Kyverno, builds and loads Sidereal images,
# installs Sidereal via Helm, and runs one probe of each built-in type to
# verify the stack end-to-end.
#
# Usage:
#   ./hack/bootstrap-kind.sh [flags]
#
# Flags:
#   --cluster-name NAME    KIND cluster name (default: sidereal-dev)
#   --skip-build           Skip make docker-build-all; use images already in Docker
#   --with-detection       Install Falco and run a detection probe (requires kernel eBPF support)
#   --teardown             Delete the KIND cluster and all associated resources
#   --help                 Show this message

set -euo pipefail

# ---------------------------------------------------------------------------
# Config / defaults
# ---------------------------------------------------------------------------

CLUSTER_NAME="sidereal-dev"
SKIP_BUILD=false
TEARDOWN=false
WITH_DETECTION=false

REGISTRY="ghcr.io/primaris-tech"
IMAGE_TAG="latest"

KYVERNO_CHART_VERSION="3.3.4"   # Kyverno app v1.13.x
FALCO_CHART_VERSION="4.18.0"    # Falco 0.39.x; update if chart version is unavailable
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
    --with-detection)
      WITH_DETECTION=true; shift ;;
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

step "Step 1 — Creating KIND cluster: ${CLUSTER_NAME}"

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

step "Step 2 — Installing Kyverno ${KYVERNO_CHART_VERSION}"

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
# Step 3: Falco (optional — only with --with-detection)
# ---------------------------------------------------------------------------

if [[ "${WITH_DETECTION}" == "true" ]]; then
  step "Step 3 — Installing Falco ${FALCO_CHART_VERSION}"
  info "Note: requires kernel eBPF support (Linux 5.8+ with BTF). May not work on all KIND hosts."

  helm repo add falcosecurity https://falcosecurity.github.io/charts --force-update >/dev/null

  if helm status falco -n falco &>/dev/null; then
    warn "Falco already installed — skipping."
  else
    helm install falco falcosecurity/falco \
      --namespace falco \
      --create-namespace \
      --version "${FALCO_CHART_VERSION}" \
      --set driver.kind=modern_ebpf \
      --set tty=true \
      --set "falco.grpc.enabled=true" \
      --set "falco.grpc.bind_address=0.0.0.0:50051" \
      --set "falco.grpc_output.enabled=true" \
      --set falcosidekick.enabled=false \
      --wait \
      --timeout 5m
    success "Falco installed."
  fi

  kubectl rollout status daemonset/falco -n falco --timeout=120s
  success "Falco ready."
else
  step "Step 3 — Falco (skipped)"
  info "Pass --with-detection to install Falco and run a detection probe."
fi

# ---------------------------------------------------------------------------
# Step 4: Build and load Sidereal images
# ---------------------------------------------------------------------------

step "Step 4 — Preparing Sidereal images"

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
  # Skip the detection image unless --with-detection is set;
  # the Rust FIPS build requires a heavier toolchain than a typical first-time setup.
  if [[ "${img}" == *"probe-detection"* && "${WITH_DETECTION}" == "false" ]]; then
    warn "Skipping detection probe image (pass --with-detection to load it)."
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
# Step 5: Install CRDs
# ---------------------------------------------------------------------------

step "Step 5 — Installing Sidereal CRDs"

kubectl apply -f "${REPO_ROOT}/config/crd/bases/"
success "CRDs installed."

# ---------------------------------------------------------------------------
# Step 6: Prepare demo namespace
#
# Done before Sidereal installs so we can retrieve the netpol target's
# ClusterIP and pass it to the Helm chart as probe.netpol.defaultTargetHost.
# Without a target host the netpol probe returns Indeterminate immediately.
# ---------------------------------------------------------------------------

step "Step 6 — Preparing demo namespace: ${DEMO_NAMESPACE}"

# Apply PSA baseline enforcement on the namespace. The admission probe's default
# bad pod sets hostPID=true, hostNetwork=true, and privileged=true — all of which
# are disallowed by the baseline standard. PSA is built into the API server and
# returns a guaranteed Forbidden (403), which the probe maps to Rejected → Effective.
# A Kyverno Policy would also work conceptually, but PSA avoids any dependency on
# Kyverno's policy evaluation returning the exact error code the probe expects.
kubectl apply -f - <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: ${DEMO_NAMESPACE}
  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/warn: restricted
EOF
success "Namespace created with PSA baseline enforcement."

# Service: gives the netpol probe a ClusterIP to target.
# The default-deny-ingress NetworkPolicy (below) will block the probe's TCP
# connection attempt → VerdictInferredDropped → Blocked → Effective.
info "Creating netpol target service..."
kubectl apply -f - <<EOF
apiVersion: v1
kind: Service
metadata:
  name: netpol-target
  namespace: ${DEMO_NAMESPACE}
spec:
  selector:
    app: netpol-target
  ports:
  - port: 80
    targetPort: 80
EOF

# Retrieve the ClusterIP (assigned synchronously by kube-apiserver).
NETPOL_TARGET_IP=""
for _ in $(seq 1 10); do
  NETPOL_TARGET_IP=$(kubectl get svc netpol-target -n "${DEMO_NAMESPACE}" \
    -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true)
  [[ -n "${NETPOL_TARGET_IP}" && "${NETPOL_TARGET_IP}" != "None" ]] && break
  sleep 1
done

if [[ -n "${NETPOL_TARGET_IP}" ]]; then
  success "Netpol target ClusterIP: ${NETPOL_TARGET_IP}"
else
  warn "Could not get ClusterIP for netpol-target; netpol probe may return Indeterminate."
fi

# NetworkPolicy: default-deny-ingress on the demo namespace.
info "Applying default-deny-ingress NetworkPolicy..."
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: ${DEMO_NAMESPACE}
spec:
  podSelector: {}
  policyTypes:
  - Ingress
EOF
success "NetworkPolicy applied."

# ---------------------------------------------------------------------------
# Step 7: Install Sidereal
# ---------------------------------------------------------------------------

step "Step 7 — Installing Sidereal"

DETECTION_BACKEND="none"
if [[ "${WITH_DETECTION}" == "true" ]]; then
  DETECTION_BACKEND="falco"
fi

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
  # Profile: Kyverno admission, conditional detection backend, tcp-inference CNI.
  "--set" "profile.admissionController=kyverno"
  "--set" "profile.signatureVerifier=kyverno"
  "--set" "profile.detectionBackend=${DETECTION_BACKEND}"
  "--set" "profile.cniObservability=tcp-inference"
  # Image tags and pull policy for locally-loaded images.
  "--set" "controller.image.tag=${IMAGE_TAG}"
  "--set" "controller.image.pullPolicy=Never"
  "--set" "probe.goImage.tag=${IMAGE_TAG}"
  "--set" "probe.goImage.pullPolicy=Never"
  "--set" "probe.bootstrapImage.tag=${IMAGE_TAG}"
  "--set" "probe.bootstrapImage.pullPolicy=Never"
  "--set" "probe.detectionImage.tag=${IMAGE_TAG}"
)

# Pass the netpol target ClusterIP so the controller injects it into probe Jobs.
# defaultTargetPort defaults to "80" in values.yaml; no override needed here.
if [[ -n "${NETPOL_TARGET_IP}" ]]; then
  HELM_ARGS+=("--set" "probe.netpol.defaultTargetHost=${NETPOL_TARGET_IP}")
fi

if [[ "${WITH_DETECTION}" == "true" ]]; then
  HELM_ARGS+=("--set" "probe.detectionImage.pullPolicy=Never")
fi

if helm status sidereal -n "${SIDEREAL_NAMESPACE}" &>/dev/null; then
  warn "Sidereal already installed — running helm upgrade."
  helm upgrade sidereal "${REPO_ROOT}/deploy/helm/sidereal/" "${HELM_ARGS[@]}" --wait --timeout 3m
else
  helm install sidereal "${REPO_ROOT}/deploy/helm/sidereal/" "${HELM_ARGS[@]}" --wait --timeout 3m
fi

success "Sidereal installed."

# ---------------------------------------------------------------------------
# Step 7: Verify installation
# ---------------------------------------------------------------------------

step "Step 8 — Verifying installation"

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
# Demo — netpol target pod
#
# Deploy a running pod in sidereal-demo so kube-proxy routes the probe's TCP
# connection to an actual endpoint. The NetworkPolicy (applied in Step 6)
# drops the ingress traffic before it reaches the pod, so the probe sees a
# timeout → VerdictInferredDropped → Blocked → Effective.
# Without a running endpoint, kube-proxy would REJECT the SYN (no endpoints)
# giving the probe a connection-refused, which maps to Indeterminate instead.
# ---------------------------------------------------------------------------

step "Demo — Deploying netpol target pod"

kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: netpol-target
  namespace: ${DEMO_NAMESPACE}
  labels:
    app: netpol-target
spec:
  containers:
  - name: target
    image: busybox:1.36
    command: ["sh", "-c", "while true; do sleep 3600; done"]
    securityContext:
      runAsNonRoot: true
      runAsUser: 65534
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
EOF

info "Waiting for netpol target pod to be ready (pulls busybox on first run)..."
kubectl wait --for=condition=Ready pod/netpol-target \
  -n "${DEMO_NAMESPACE}" --timeout=90s \
  && success "Netpol target pod ready." \
  || warn "Netpol target pod not ready within timeout; netpol probe may return Indeterminate."

# ---------------------------------------------------------------------------
# Demo — AO authorization (detection probes only)
# ---------------------------------------------------------------------------

if [[ "${WITH_DETECTION}" == "true" ]]; then
  step "Demo — Creating SiderealAOAuthorization for detection probe"
  info "Detection probes require an active AO authorization scoped to techniques and namespaces."

  # Compute a 90-day validity window using portable date syntax.
  AO_VALID_FROM=$(date -u +"%Y-%m-%dT00:00:00Z")
  AO_EXPIRES_AT=$(date -u -v+90d +"%Y-%m-%dT23:59:59Z" 2>/dev/null || \
                  date -u -d "+90 days" +"%Y-%m-%dT23:59:59Z")

  kubectl apply -f - <<EOF
apiVersion: sidereal.cloud/v1alpha1
kind: SiderealAOAuthorization
metadata:
  name: ao-auth-detection-demo
  namespace: ${SIDEREAL_NAMESPACE}
spec:
  aoName: "Bootstrap Operator (demo authorization)"
  authorizedTechniques:
    - "T1059"
  authorizedNamespaces:
    - ${DEMO_NAMESPACE}
  validFrom: "${AO_VALID_FROM}"
  expiresAt: "${AO_EXPIRES_AT}"
  justification: >-
    Demo authorization created by bootstrap-kind.sh to validate the detection
    probe workflow. Authorizes T1059 (Command and Scripting Interpreter) in
    ${DEMO_NAMESPACE} for continuous monitoring validation per CA-2.
EOF
  success "AO authorization created."
fi

# ---------------------------------------------------------------------------
# Demo — apply one probe of each built-in type
# ---------------------------------------------------------------------------

step "Demo — Applying probes"

# rbac, secret, netpol, and admission run on KIND with no extra infrastructure.
kubectl apply -f - <<EOF
---
apiVersion: sidereal.cloud/v1alpha1
kind: SiderealProbe
metadata:
  name: rbac-getting-started
  namespace: ${SIDEREAL_NAMESPACE}
spec:
  profile: rbac
  targetNamespace: ${DEMO_NAMESPACE}
  executionMode: observe
  intervalSeconds: 300
  mitreAttackId: "T1078"
  controlMappings:
    nist-800-53:
      - AC-6
      - AC-6(5)
---
apiVersion: sidereal.cloud/v1alpha1
kind: SiderealProbe
metadata:
  name: secret-getting-started
  namespace: ${SIDEREAL_NAMESPACE}
spec:
  profile: secret
  targetNamespace: ${DEMO_NAMESPACE}
  executionMode: observe
  intervalSeconds: 300
  mitreAttackId: "T1552"
  controlMappings:
    nist-800-53:
      - AC-6(10)
      - IA-5(7)
---
apiVersion: sidereal.cloud/v1alpha1
kind: SiderealProbe
metadata:
  name: netpol-getting-started
  namespace: ${SIDEREAL_NAMESPACE}
spec:
  profile: netpol
  targetNamespace: ${DEMO_NAMESPACE}
  executionMode: observe
  intervalSeconds: 300
  mitreAttackId: "T1046"
  controlMappings:
    nist-800-53:
      - SC-7
      - SC-7(5)
---
apiVersion: sidereal.cloud/v1alpha1
kind: SiderealProbe
metadata:
  name: admission-getting-started
  namespace: ${SIDEREAL_NAMESPACE}
spec:
  profile: admission
  targetNamespace: ${DEMO_NAMESPACE}
  executionMode: observe
  intervalSeconds: 300
  controlMappings:
    nist-800-53:
      - CM-7(2)
      - CM-7(5)
EOF
success "Probes applied: rbac, secret, netpol, admission."

if [[ "${WITH_DETECTION}" == "true" ]]; then
  kubectl apply -f - <<EOF
apiVersion: sidereal.cloud/v1alpha1
kind: SiderealProbe
metadata:
  name: detection-getting-started
  namespace: ${SIDEREAL_NAMESPACE}
spec:
  profile: detection
  targetNamespace: ${DEMO_NAMESPACE}
  executionMode: observe
  intervalSeconds: 300
  mitreAttackId: "T1059"
  aoAuthorizationRef: ao-auth-detection-demo
  controlMappings:
    nist-800-53:
      - AU-6
      - SI-4
EOF
  success "Detection probe applied."
fi

# ---------------------------------------------------------------------------
# Demo — wait for all results
# ---------------------------------------------------------------------------

step "Demo — Waiting for probe results"

declare -a PROBES_TO_WAIT=(
  "rbac-getting-started"
  "secret-getting-started"
  "netpol-getting-started"
  "admission-getting-started"
)
if [[ "${WITH_DETECTION}" == "true" ]]; then
  PROBES_TO_WAIT+=("detection-getting-started")
fi

info "Waiting up to 120s for ${#PROBES_TO_WAIT[@]} probe(s) to complete..."
echo ""

declare -a pending=("${PROBES_TO_WAIT[@]}")
MAX_ITERS=24  # 24 × 5s = 120s

for iter in $(seq 1 "${MAX_ITERS}"); do
  declare -a remaining=()
  for probe in "${pending[@]}"; do
    if kubectl get siderealproberesults -n "${SIDEREAL_NAMESPACE}" \
        -l "sidereal.cloud/probe-name=${probe}" \
        --no-headers 2>/dev/null | grep -q .; then
      success "Result received: ${probe}"
    else
      remaining+=("${probe}")
    fi
  done

  pending=()
  [[ ${#remaining[@]} -gt 0 ]] && pending=("${remaining[@]}")
  [[ ${#pending[@]} -eq 0 ]] && break

  [[ "${iter}" -lt "${MAX_ITERS}" ]] && {
    info "Pending: ${pending[*]} (${iter}/${MAX_ITERS})"
    sleep 5
  }
done

if [[ ${#pending[@]} -gt 0 ]]; then
  for probe in "${pending[@]}"; do
    warn "No result received for: ${probe} (Job may still be running)"
  done
fi

# ---------------------------------------------------------------------------
# Demo — display results
# ---------------------------------------------------------------------------

echo ""
step "Demo — Results"
echo ""
kubectl get siderealproberesults -n "${SIDEREAL_NAMESPACE}" \
  -o custom-columns=\
"NAME:.metadata.name,\
PROFILE:.spec.probe.profile,\
OUTCOME:.spec.result.outcome,\
EFFECTIVENESS:.spec.result.controlEffectiveness,\
INTEGRITY:.spec.result.integrityStatus"
echo ""

info "To inspect a result in full:"
info "  kubectl describe siderealproberesult <name> -n ${SIDEREAL_NAMESPACE}"
echo ""
info "To check each probe's status and recent result history:"
info "  kubectl get siderealprobes -n ${SIDEREAL_NAMESPACE}"
echo ""

# ---------------------------------------------------------------------------
# Detection probe workflow note (shown when --with-detection was not used)
# ---------------------------------------------------------------------------

if [[ "${WITH_DETECTION}" == "false" ]]; then
  echo -e "${BOLD}Detection probe (not run in this environment):${NC}"
  echo ""
  echo "  The detection probe validates your runtime security layer by firing"
  echo "  a synthetic syscall pattern and verifying the detection backend"
  echo "  (Falco or Tetragon) raised the expected alert."
  echo ""
  echo "  Requirements:"
  echo "    1. Falco or Tetragon installed and reachable (Falco gRPC on :50051)"
  echo "    2. Sidereal installed with profile.detectionBackend=falco (or tetragon)"
  echo "    3. A SiderealAOAuthorization scoping the techniques and namespaces to test"
  echo ""
  echo "  To run the full suite including detection:"
  echo "    ./hack/bootstrap-kind.sh --with-detection"
  echo ""
  echo "  The AO authorization is required before creating a detection probe:"
  echo ""
  cat <<'DETECTION_EXAMPLE'
  kubectl apply -f - <<EOF
  apiVersion: sidereal.cloud/v1alpha1
  kind: SiderealAOAuthorization
  metadata:
    name: ao-auth-detection-demo
    namespace: sidereal-system
  spec:
    aoName: "Your Name, ISSO / Authorizing Official"
    authorizedTechniques:
      - "T1059"   # Command and Scripting Interpreter
    authorizedNamespaces:
      - sidereal-demo
    validFrom: "2026-04-16T00:00:00Z"
    expiresAt: "2026-07-15T23:59:59Z"
    justification: >-
      Authorize detection validation for command execution (T1059) in
      the demo namespace per CA-2 continuous monitoring requirements.
  EOF
DETECTION_EXAMPLE
  echo ""
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
