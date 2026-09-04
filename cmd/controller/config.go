package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/primaris-tech/sidereal/internal/controller"
)

// parseCustomServiceAccounts accepts the registrations rendered by the Helm chart.
// Missing configuration leaves the allowlist empty.
func parseCustomServiceAccounts(raw string) (map[string]bool, error) {
	registered := make(map[string]bool)
	if raw == "" {
		return registered, nil
	}
	var accounts []struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	}
	if err := json.Unmarshal([]byte(raw), &accounts); err != nil {
		return nil, fmt.Errorf("parse CUSTOM_PROBE_SERVICE_ACCOUNTS: %w", err)
	}
	for _, account := range accounts {
		if account.Name == "" || strings.TrimSpace(account.Name) != account.Name {
			return nil, fmt.Errorf("custom probe ServiceAccount name must be nonempty and have no surrounding whitespace")
		}
		if account.Namespace != "" && account.Namespace != controller.SystemNamespace {
			return nil, fmt.Errorf("custom probe ServiceAccount %q must be in namespace %q", account.Name, controller.SystemNamespace)
		}
		registered[account.Name] = true
	}
	return registered, nil
}
