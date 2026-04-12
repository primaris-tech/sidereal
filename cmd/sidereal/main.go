package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	siderealv1alpha1 "github.com/primaris-tech/sidereal/api/v1alpha1"
	"github.com/primaris-tech/sidereal/internal/discovery"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "discover":
		if err := runDiscover(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "version":
		fmt.Println("sidereal v0.1.0-dev")
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`sidereal - Kubernetes security control validation operator

Usage:
  sidereal <command> [flags]

Commands:
  discover    Discover security controls and generate probe configurations
  version     Print version information
  help        Print this help message

Use "sidereal <command> --help" for more information about a command.`)
}

func runDiscover(args []string) error {
	fs := flag.NewFlagSet("discover", flag.ExitOnError)
	probeType := fs.String("type", "", "Probe type to discover (rbac, netpol, admission, secret, detection). Empty for all.")
	namespace := fs.String("namespace", "", "Limit discovery to a specific namespace")
	output := fs.String("output", "", "Output directory or file for generated probe YAML. Empty for stdout.")
	dryRun := fs.Bool("dry-run", false, "Show what would be discovered without writing files")
	kubeconfig := fs.String("kubeconfig", "", "Path to kubeconfig file")
	outputFormat := fs.String("format", "yaml", "Output format: yaml or json")

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Build Kubernetes client.
	c, err := buildClient(*kubeconfig)
	if err != nil {
		return fmt.Errorf("failed to build Kubernetes client: %w", err)
	}

	ctx := context.Background()
	engine := discovery.NewEngine()

	var recs []discovery.Recommendation

	if *probeType != "" {
		pt := siderealv1alpha1.ProbeType(*probeType)
		recs, err = engine.RunByType(ctx, c, pt)
	} else {
		recs, err = engine.RunAll(ctx, c)
	}
	if err != nil {
		return fmt.Errorf("discovery failed: %w", err)
	}

	// Filter by namespace if specified.
	if *namespace != "" {
		var filtered []discovery.Recommendation
		for _, rec := range recs {
			if rec.ProbeTemplate.TargetNamespace == *namespace ||
				rec.SourceResource.Namespace == *namespace {
				filtered = append(filtered, rec)
			}
		}
		recs = filtered
	}

	if *dryRun {
		fmt.Printf("Would generate %d probe recommendations:\n\n", len(recs))
		for _, rec := range recs {
			fmt.Printf("  [%s] %s/%s -> %s probe in %s (confidence: %s)\n",
				rec.SourceResource.Kind,
				rec.SourceResource.Namespace,
				rec.SourceResource.Name,
				rec.ProbeTemplate.ProbeType,
				rec.ProbeTemplate.TargetNamespace,
				rec.Confidence,
			)
		}
		return nil
	}

	// Convert recommendations to SiderealProbe resources (CLI outputs probes, not recommendations).
	var probes []siderealv1alpha1.SiderealProbe
	for _, rec := range recs {
		probe := siderealv1alpha1.SiderealProbe{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "sidereal.cloud/v1alpha1",
				Kind:       "SiderealProbe",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      discovery.RecommendationName(rec.SourceResource, ""),
				Namespace: "sidereal-system",
			},
			Spec: rec.ProbeTemplate,
		}
		if rec.ControlMappings != nil {
			probe.Spec.ControlMappings = rec.ControlMappings
		}
		probes = append(probes, probe)
	}

	if len(probes) == 0 {
		fmt.Println("No probes discovered.")
		return nil
	}

	// Output probes.
	if *output != "" {
		return writeProbes(probes, *output, *outputFormat)
	}

	// Write to stdout.
	for i, probe := range probes {
		if i > 0 {
			fmt.Println("---")
		}
		data, err := marshalProbe(probe, *outputFormat)
		if err != nil {
			return err
		}
		fmt.Print(string(data))
	}

	return nil
}

func buildClient(kubeconfigPath string) (client.Client, error) {
	if kubeconfigPath == "" {
		kubeconfigPath = os.Getenv("KUBECONFIG")
	}
	if kubeconfigPath == "" {
		home, _ := os.UserHomeDir()
		kubeconfigPath = filepath.Join(home, ".kube", "config")
	}

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		return nil, err
	}

	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = siderealv1alpha1.AddToScheme(scheme)

	return client.New(config, client.Options{Scheme: scheme})
}

func marshalProbe(probe siderealv1alpha1.SiderealProbe, format string) ([]byte, error) {
	switch format {
	case "json":
		return json.MarshalIndent(probe, "", "  ")
	default:
		return yaml.Marshal(probe)
	}
}

func writeProbes(probes []siderealv1alpha1.SiderealProbe, outputPath, format string) error {
	// Check if output is a directory.
	info, err := os.Stat(outputPath)
	if err == nil && info.IsDir() {
		// Write each probe to a separate file.
		for _, probe := range probes {
			ext := "yaml"
			if format == "json" {
				ext = "json"
			}
			filename := filepath.Join(outputPath, fmt.Sprintf("%s.%s", probe.Name, ext))
			data, err := marshalProbe(probe, format)
			if err != nil {
				return err
			}
			if err := os.WriteFile(filename, data, 0644); err != nil {
				return fmt.Errorf("failed to write %s: %w", filename, err)
			}
			fmt.Printf("Wrote %s\n", filename)
		}
		return nil
	}

	// Write all probes to a single file.
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", outputPath, err)
	}
	defer f.Close()

	for i, probe := range probes {
		if i > 0 {
			fmt.Fprintln(f, "---")
		}
		data, err := marshalProbe(probe, format)
		if err != nil {
			return err
		}
		f.Write(data)
	}

	fmt.Printf("Wrote %d probes to %s\n", len(probes), outputPath)
	return nil
}
