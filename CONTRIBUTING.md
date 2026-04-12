# Contributing to Sidereal

## Development Setup

### Prerequisites

- Go 1.25+
- Rust 1.86+ (for detection probe)
- Docker
- Helm 3.12+
- kubectl

### Clone and build

```bash
git clone https://github.com/primaris-tech/sidereal.git
cd sidereal
make build
```

### Run tests

```bash
# Go unit tests
make test

# Rust detection probe tests
make test-detection-probe

# E2E tests (requires envtest binaries)
make test-e2e

# FIPS build + verification
make build-fips
make verify-fips
```

### Lint

```bash
# Go
make lint

# Rust
make lint-detection-probe

# Helm
make helm-lint
```

## Code Organization

```
api/v1alpha1/          CRD type definitions
cmd/                   Binary entrypoints (controller, probes, CLI)
internal/controller/   Controller reconcilers
internal/discovery/    Cluster discovery engine
internal/hmac/         HMAC key derivation and verification
internal/probe/        Shared probe runner framework
internal/backend/      Pluggable backend interfaces (detection, networkpolicy, export)
internal/crosswalk/    Multi-framework control mapping
internal/report/       Report generation engine
probes/                Probe implementations (rbac, secret, admission, netpol)
detection-probe/       Rust detection probe
deploy/helm/sidereal/  Helm chart
build/                 Dockerfiles
test/e2e/              E2E integration tests
compliance/            ATO documentation package
```

## Pull Request Process

1. Create a feature branch from `main`
2. Write tests for new functionality
3. Run `make test` and `make lint` locally
4. Open a PR against `main`
5. All CI checks must pass
6. Commits must be signed

## Coding Standards

- Follow existing patterns in the codebase
- All exported functions and types in new files should have doc comments
- Security-critical paths (`internal/hmac/`, `internal/probe/`, `detection-probe/`) require careful review
- FIPS cryptography only: use `crypto/` stdlib (routes to BoringCrypto) or `aws-lc-rs` for Rust
- Probe runners must be non-root, read-only filesystem, all capabilities dropped

## Commit Signing

All commits must be signed. We use SSH signing with hardware security keys (YubiKey). See [GitHub's documentation](https://docs.github.com/en/authentication/managing-commit-signature-verification) for setup.
