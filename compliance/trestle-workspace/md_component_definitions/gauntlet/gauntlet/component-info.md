---
x-trestle-template-version: "0.0.1"
x-trestle-comp-type: software
---

# Gauntlet — Component Definition

## Component Metadata

| Field | Value |
|---|---|
| Component Name | Gauntlet |
| Component Type | Software |
| Version | See CHANGELOG |
| Baseline | NIST SP 800-53 Rev 5 — High |
| Last Updated | See git history |

## Description

Gauntlet is a Kubernetes-native security operator for continuous security control
validation on Federal systems. It runs a continuous loop of targeted, low-impact
security probes against a live cluster, produces NIST 800-53-mapped audit records
for every execution, and exports them to a SIEM as evidence for ATO packages and
continuous monitoring reports under FISMA, FedRAMP, and NIST 800-53.

## Probe Surfaces

| Probe | NIST Controls |
|---|---|
| RBAC | AC-2, AC-3, AC-6 |
| NetworkPolicy | SC-7, SC-8 |
| Admission Control | CM-6, CM-7 |
| Secret Access | AC-3, AC-4 |
| Detection Coverage | SI-3, SI-4, SI-7 |

## Authoring Instructions

Each control implementation is a markdown file in the corresponding family
subdirectory. Files are named by control ID (e.g., `au-9.md`).

To compile to OSCAL:
```
trestle assemble component-definition -n gauntlet
```

To validate:
```
oscal-cli component-definition validate \
  -f component-definitions/gauntlet/component-definition.json
```

## Status Legend

Each control file carries one of the following statuses in its frontmatter:

- `implemented` — Implementation is complete and documented
- `partial` — Implementation is in progress; gaps noted in the file
- `planned` — Implementation is planned but not yet built
- `inherited` — Satisfied by the underlying Kubernetes platform
- `not-applicable` — Control does not apply to Gauntlet's context
