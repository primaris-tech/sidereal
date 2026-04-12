# Sidereal Makefile
# Kubernetes-native security operator for continuous control validation

# Image registry and version
REGISTRY ?= ghcr.io/primaris-tech
VERSION ?= latest

# Image URLs
IMG ?= $(REGISTRY)/sidereal-controller:$(VERSION)
IMG_PROBE_RBAC ?= $(REGISTRY)/sidereal-probe-rbac:$(VERSION)
IMG_PROBE_SECRET ?= $(REGISTRY)/sidereal-probe-secret:$(VERSION)
IMG_PROBE_ADMISSION ?= $(REGISTRY)/sidereal-probe-admission:$(VERSION)
IMG_PROBE_NETPOL ?= $(REGISTRY)/sidereal-probe-netpol:$(VERSION)
IMG_PROBE_DETECTION ?= $(REGISTRY)/sidereal-probe-detection:$(VERSION)
IMG_BOOTSTRAP ?= $(REGISTRY)/sidereal-bootstrap:$(VERSION)

# controller-gen and other tool binaries
CONTROLLER_GEN ?= go run sigs.k8s.io/controller-tools/cmd/controller-gen@v0.20.1
GOLANGCI_LINT ?= golangci-lint

# Get the currently used golang install path
GOBIN ?= $(shell go env GOBIN)
ifeq (,$(GOBIN))
GOBIN = $(shell go env GOPATH)/bin
endif

# envtest setup
LOCALBIN ?= $(shell pwd)/bin
ENVTEST ?= go run sigs.k8s.io/controller-runtime/tools/setup-envtest@latest
ENVTEST_K8S_VERSION ?= 1.31.0

.PHONY: all
all: generate manifests build

##@ General

.PHONY: help
help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: generate
generate: ## Generate deepcopy functions
	$(CONTROLLER_GEN) object paths="./api/..."

.PHONY: manifests
manifests: ## Generate CRD manifests
	$(CONTROLLER_GEN) crd paths="./api/..." output:crd:artifacts:config=config/crd/bases

.PHONY: fmt
fmt: ## Run go fmt
	go fmt ./...

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: lint
lint: ## Run golangci-lint
	$(GOLANGCI_LINT) run

##@ Build

.PHONY: build
build: ## Build all Go binaries
	go build -o bin/controller ./cmd/controller/
	go build -o bin/probe-rbac ./cmd/probe-rbac/
	go build -o bin/probe-netpol ./cmd/probe-netpol/
	go build -o bin/probe-admission ./cmd/probe-admission/
	go build -o bin/probe-secret ./cmd/probe-secret/
	go build -o bin/probe-bootstrap ./cmd/probe-bootstrap/
	go build -o bin/sidereal ./cmd/sidereal/

.PHONY: build-fips
build-fips: ## Build all Go binaries with BoringCrypto FIPS
	GOEXPERIMENT=boringcrypto go build -trimpath -o bin/controller ./cmd/controller/
	GOEXPERIMENT=boringcrypto go build -trimpath -o bin/probe-rbac ./cmd/probe-rbac/
	GOEXPERIMENT=boringcrypto go build -trimpath -o bin/probe-netpol ./cmd/probe-netpol/
	GOEXPERIMENT=boringcrypto go build -trimpath -o bin/probe-admission ./cmd/probe-admission/
	GOEXPERIMENT=boringcrypto go build -trimpath -o bin/probe-secret ./cmd/probe-secret/
	GOEXPERIMENT=boringcrypto go build -trimpath -o bin/probe-bootstrap ./cmd/probe-bootstrap/
	GOEXPERIMENT=boringcrypto go build -trimpath -o bin/sidereal ./cmd/sidereal/

.PHONY: build-controller
build-controller: ## Build controller binary only
	go build -o bin/controller ./cmd/controller/

.PHONY: verify-fips
verify-fips: ## Verify FIPS cryptography in built binaries
	@./hack/verify-fips.sh

.PHONY: verify-fips-docker
verify-fips-docker: ## Verify FIPS labels on Docker images
	@./hack/verify-fips.sh --docker

##@ Test

.PHONY: test
test: ## Run unit tests
	go test ./... -coverprofile cover.out

.PHONY: test-e2e
test-e2e: envtest ## Run end-to-end tests (requires envtest binaries)
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path)" \
		go test ./test/e2e/... -v -count=1 -timeout 300s

.PHONY: test-integration
test-integration: ## Run integration tests
	go test ./test/integration/... -v -count=1

##@ Docker

.PHONY: docker-build
docker-build: ## Build controller Docker image
	docker build -t $(IMG) -f build/Dockerfile.controller .

.PHONY: docker-build-probes
docker-build-probes: ## Build all probe Docker images
	docker build --build-arg PROBE_CMD=probe-rbac -t $(IMG_PROBE_RBAC) -f build/Dockerfile.probe-go .
	docker build --build-arg PROBE_CMD=probe-secret -t $(IMG_PROBE_SECRET) -f build/Dockerfile.probe-go .
	docker build --build-arg PROBE_CMD=probe-admission -t $(IMG_PROBE_ADMISSION) -f build/Dockerfile.probe-go .
	docker build --build-arg PROBE_CMD=probe-netpol -t $(IMG_PROBE_NETPOL) -f build/Dockerfile.probe-go .
	docker build -t $(IMG_PROBE_DETECTION) -f build/Dockerfile.probe-detection detection-probe/

.PHONY: docker-build-bootstrap
docker-build-bootstrap: ## Build bootstrap Docker image
	docker build -t $(IMG_BOOTSTRAP) -f build/Dockerfile.bootstrap .

.PHONY: docker-build-all
docker-build-all: docker-build docker-build-probes docker-build-bootstrap ## Build all Docker images

.PHONY: docker-push
docker-push: ## Push all Docker images
	docker push $(IMG)
	docker push $(IMG_PROBE_RBAC)
	docker push $(IMG_PROBE_SECRET)
	docker push $(IMG_PROBE_ADMISSION)
	docker push $(IMG_PROBE_NETPOL)
	docker push $(IMG_PROBE_DETECTION)
	docker push $(IMG_BOOTSTRAP)

##@ Helm

.PHONY: helm-lint
helm-lint: ## Lint Helm chart
	helm lint deploy/helm/sidereal/

.PHONY: helm-template
helm-template: ## Render Helm chart templates
	helm template sidereal deploy/helm/sidereal/

.PHONY: manifests-static
manifests-static: ## Generate static manifests for all deployment profiles
	@mkdir -p deploy/static
	@for profile in kyverno-cilium-falco opa-calico-tetragon kyverno-eks opa-aks kyverno-gke opa-rke2; do \
		mkdir -p deploy/static/$$profile; \
		helm template sidereal deploy/helm/sidereal/ --set profile.name=$$profile > deploy/static/$$profile/manifests.yaml 2>/dev/null || true; \
	done

##@ Rust Detection Probe

.PHONY: build-detection-probe
build-detection-probe: ## Build Rust detection probe
	cd detection-probe && cargo build --release

.PHONY: test-detection-probe
test-detection-probe: ## Test Rust detection probe
	cd detection-probe && cargo test

.PHONY: lint-detection-probe
lint-detection-probe: ## Lint Rust detection probe
	cd detection-probe && cargo clippy -- -D warnings

##@ Tools

.PHONY: envtest
envtest: ## Download envtest binaries
	@$(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path > /dev/null

##@ Clean

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf bin/ cover.out
	cd detection-probe && cargo clean 2>/dev/null || true
