# Sidereal Makefile
# Kubernetes-native security operator for continuous control validation

# Image URL to use all building/pushing image targets
IMG ?= ghcr.io/primaris-tech/sidereal-controller:latest
IMG_PROBE_GO ?= ghcr.io/primaris-tech/sidereal-probe-go:latest
IMG_PROBE_DETECTION ?= ghcr.io/primaris-tech/sidereal-probe-detection:latest

# controller-gen and other tool binaries
CONTROLLER_GEN ?= go run sigs.k8s.io/controller-tools/cmd/controller-gen@v0.20.1
GOLANGCI_LINT ?= golangci-lint

# Get the currently used golang install path
GOBIN ?= $(shell go env GOBIN)
ifeq (,$(GOBIN))
GOBIN = $(shell go env GOPATH)/bin
endif

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

.PHONY: build-controller
build-controller: ## Build controller binary only
	go build -o bin/controller ./cmd/controller/

##@ Test

.PHONY: test
test: ## Run unit tests
	go test ./... -coverprofile cover.out

.PHONY: test-e2e
test-e2e: ## Run end-to-end tests (requires kind cluster)
	go test ./test/e2e/... -v -count=1

.PHONY: test-integration
test-integration: ## Run integration tests
	go test ./test/integration/... -v -count=1

##@ Docker

.PHONY: docker-build
docker-build: ## Build controller Docker image
	docker build -t $(IMG) -f build/Dockerfile.controller .

.PHONY: docker-build-probes
docker-build-probes: ## Build probe Docker images
	docker build -t $(IMG_PROBE_GO) -f build/Dockerfile.probe-go .
	docker build -t $(IMG_PROBE_DETECTION) -f build/Dockerfile.probe-detection detection-probe/

.PHONY: docker-push
docker-push: ## Push controller Docker image
	docker push $(IMG)

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

##@ Clean

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf bin/ cover.out
	cd detection-probe && cargo clean 2>/dev/null || true
