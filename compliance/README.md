# Sidereal Compliance Documentation

This directory contains the Phase 1 ATO documentation package for Sidereal.
It is structured to give deploying agencies everything needed to run their own
ATO with minimal authoring effort.

## Deployment Profiles

Sidereal's compliance documentation references **abstract capabilities** (e.g.,
"admission enforcement layer", "detection backend", "CNI observability") rather
than specific tools. Each deployment has a **profile** that binds these abstract
capabilities to concrete tools.

Pre-built profiles are in `profiles/`:
- `kyverno-cilium-falco.md` — Kyverno + Cilium/Hubble + Falco (default)
- `opa-calico-tetragon.md` — OPA/Gatekeeper + Calico + Tetragon
- `kyverno-eks.md` — Kyverno + VPC CNI + Falco (Amazon EKS)
- `opa-aks.md` — OPA/Gatekeeper + Azure CNI + Falco (Azure AKS)
- `kyverno-gke.md` — Kyverno + Dataplane V2 + Falco (Google GKE)
- `opa-rke2.md` — OPA/Gatekeeper + Tetragon (RKE2/k3s on-premises)

Each profile document contains:
- Capability-to-tool binding table
- Helm profile configuration values
- Admission policy resources rendered for that profile
- Connection parameters (ports, protocols, authentication)
- Profile-specific SAP test commands
- Evidence collection commands

When compiling the ATO package for a specific deployment, the agency selects
a profile and the compiled output names the concrete tools — because that is
what the assessor tests.

## Directory Structure

```
compliance/
  profiles/                   # Deployment profile binding documents
  trestle-workspace/          # Trestle project root — author here
    .trestle/                 # Trestle configuration
    md_component_definitions/ # Human-readable markdown (edit these)
      sidereal/
        sidereal/
          nist_sp_800-53_rev5_HIGH/
            ac/               # Access Control implementations
            au/               # Audit and Accountability
            ca/               # Assessment, Authorization, Monitoring
            cm/               # Configuration Management
            cp/               # Contingency Planning
            ia/               # Identification and Authentication
            ir/               # Incident Response
            ps/               # Personnel Security
            pt/               # PII Processing and Transparency
            ra/               # Risk Assessment
            sa/               # System and Services Acquisition
            sc/               # System and Communications Protection
            si/               # System and Information Integrity
            sr/               # Supply Chain Risk Management
    component-definitions/    # Compiled OSCAL output (generated — do not edit)
    system-security-plans/    # SSP template (generated)
    assessment-plans/         # SAP template (generated)
    assessment-results/       # Runtime output from SiderealProbeResult (generated)
    plan-of-action-and-milestones/ # POA&M (generated from SiderealIncident)
  oscal/                      # Final compiled OSCAL artifacts for distribution
  plans/                      # Supporting plans (standalone markdown)
  diagrams/                   # Architecture, boundary, and data flow diagrams
  crm/                        # Customer Responsibility Matrix

## Authoring Workflow

1. Edit markdown files in `trestle-workspace/md_component_definitions/`
2. Compile: `trestle assemble component-definition -n sidereal`
3. Validate: `oscal-cli component-definition validate -f trestle-workspace/component-definitions/sidereal/component-definition.json`
4. Copy compiled artifact to `oscal/` for distribution

CI runs steps 2 and 3 automatically on every commit.

## For Deploying Agencies

Start with:
1. `crm/customer-responsibility-matrix.md` — understand your residual obligations
2. `oscal/component-definition.json` — import into your OSCAL SSP tooling
3. `plans/` — customize supporting plans for your environment
4. `diagrams/` — reference for your SSP boundary and architecture sections
```
