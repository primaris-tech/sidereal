package main

import (
	"context"

	"github.com/primaris-tech/sidereal/internal/probe"
	"github.com/primaris-tech/sidereal/probes/netpol"
)

func main() {
	probe.Run(func(ctx context.Context, cfg probe.Config) probe.Result {
		return netpol.Execute(ctx, cfg)
	})
}
