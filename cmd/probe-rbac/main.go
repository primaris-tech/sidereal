package main

import (
	"context"

	"k8s.io/client-go/kubernetes"

	"github.com/primaris-tech/sidereal/internal/probe"
	"github.com/primaris-tech/sidereal/probes/rbac"
)

func main() {
	probe.RunWithClient(func(ctx context.Context, clientset kubernetes.Interface, cfg probe.Config) probe.Result {
		return rbac.Execute(ctx, clientset, cfg)
	})
}
