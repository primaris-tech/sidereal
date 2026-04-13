// Bootstrap verification Job — runs as a Helm pre-install hook to verify
// cluster prerequisites before Sidereal installation.
//
// Checks:
//   - Admission controller CRDs exist (Kyverno or OPA/Gatekeeper)
//   - Kubernetes version meets minimum requirements
//
// Exit 0 on success, exit 1 on failure with diagnostic output.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
)

// Known admission controller CRDs to check for.
var admissionCRDs = map[string][]string{
	"kyverno": {
		"clusterpolicies.kyverno.io",
		"policies.kyverno.io",
	},
	"gatekeeper": {
		"constrainttemplates.templates.gatekeeper.sh",
	},
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	config, err := rest.InClusterConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: failed to get in-cluster config: %v\n", err)
		os.Exit(1)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: failed to create clientset: %v\n", err)
		os.Exit(1)
	}

	extClient, err := apiextensionsclient.NewForConfig(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: failed to create apiextensions clientset: %v\n", err)
		os.Exit(1)
	}

	passed := true

	// Check Kubernetes version.
	if err := checkKubernetesVersion(clientset.Discovery()); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		passed = false
	} else {
		fmt.Println("PASS: Kubernetes version meets minimum requirements")
	}

	// Check for admission controller CRDs — skipped if REQUIRE_ADMISSION_CONTROLLER=false.
	requireAdmission := os.Getenv("REQUIRE_ADMISSION_CONTROLLER") != "false"
	if requireAdmission {
		foundAdmission := false
		for provider, crds := range admissionCRDs {
			allFound := true
			for _, crd := range crds {
				if err := checkCRDExists(ctx, extClient, crd); err != nil {
					allFound = false
					break
				}
			}
			if allFound {
				fmt.Printf("PASS: %s admission controller CRDs found\n", provider)
				foundAdmission = true
				break
			}
		}
		if !foundAdmission {
			fmt.Fprintf(os.Stderr, "FAIL: no supported admission controller found (need Kyverno or Gatekeeper)\n")
			passed = false
		}
	} else {
		fmt.Println("SKIP: admission controller check disabled (requireAdmissionController=false)")
	}

	if !passed {
		fmt.Fprintf(os.Stderr, "\nBootstrap verification FAILED. Sidereal requires a supported admission controller.\n")
		os.Exit(1)
	}

	fmt.Println("\nBootstrap verification PASSED. Cluster meets Sidereal prerequisites.")
}

func checkKubernetesVersion(disco discovery.DiscoveryInterface) error {
	info, err := disco.ServerVersion()
	if err != nil {
		return fmt.Errorf("kubernetes version: failed to query: %v", err)
	}

	fmt.Printf("  Kubernetes version: %s\n", info.GitVersion)

	// Minimum: v1.26 (for CEL validation rules support).
	var major, minor int
	fmt.Sscanf(info.Major, "%d", &major)
	fmt.Sscanf(info.Minor, "%d", &minor)

	if major < 1 || (major == 1 && minor < 26) {
		return fmt.Errorf("kubernetes version %s is below minimum v1.26", info.GitVersion)
	}

	return nil
}

func checkCRDExists(ctx context.Context, client apiextensionsclient.Interface, crdName string) error {
	_, err := client.ApiextensionsV1().CustomResourceDefinitions().Get(ctx, crdName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("CRD %s not found: %v", crdName, err)
	}
	return nil
}

// Ensure apiextensionsv1 is referenced for the scheme.
var _ = apiextensionsv1.SchemeGroupVersion
