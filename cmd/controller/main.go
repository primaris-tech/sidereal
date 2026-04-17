package main

import (
	"flag"
	"os"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	siderealv1alpha1 "github.com/primaris-tech/sidereal/api/v1alpha1"
	"github.com/primaris-tech/sidereal/internal/controller"
	"github.com/primaris-tech/sidereal/internal/crosswalk"
	"github.com/primaris-tech/sidereal/internal/discovery"
	_ "github.com/primaris-tech/sidereal/internal/metrics"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(siderealv1alpha1.AddToScheme(scheme))
}

func main() {
	var metricsAddr string
	var healthAddr string
	var enableLeaderElection bool

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metrics endpoint binds to.")
	flag.StringVar(&healthAddr, "health-probe-bind-address", ":8081", "The address the health probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")

	opts := zap.Options{Development: false}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr,
		},
		HealthProbeBindAddress: healthAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "sidereal-controller-leader",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	probeGoImage := os.Getenv("PROBE_GO_IMAGE")
	if probeGoImage == "" {
		probeGoImage = "ghcr.io/primaris-tech/sidereal-probe-go:latest"
	}
	probeDetectionImage := os.Getenv("PROBE_DETECTION_IMAGE")
	if probeDetectionImage == "" {
		probeDetectionImage = "ghcr.io/primaris-tech/sidereal-probe-detection:latest"
	}

	if err := (&controller.ProbeSchedulerReconciler{
		Client:                mgr.GetClient(),
		ProbeGoImage:          probeGoImage,
		ProbeDetectionImage:   probeDetectionImage,
		ProbeNetpolTargetHost: os.Getenv("PROBE_NETPOL_DEFAULT_TARGET_HOST"),
		ProbeNetpolTargetPort: os.Getenv("PROBE_NETPOL_DEFAULT_TARGET_PORT"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ProbeScheduler")
		os.Exit(1)
	}

	crosswalkResolver := crosswalk.NewResolver()

	if err := (&controller.ResultReconciler{
		Client:    mgr.GetClient(),
		Crosswalk: crosswalkResolver,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ResultReconciler")
		os.Exit(1)
	}

	if err := (&controller.IncidentReconciler{
		Client: mgr.GetClient(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "IncidentReconciler")
		os.Exit(1)
	}

	if err := (&controller.AlertReconciler{
		Client: mgr.GetClient(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "AlertReconciler")
		os.Exit(1)
	}

	if err := (&controller.AuthorizationReconciler{
		Client: mgr.GetClient(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "AuthorizationReconciler")
		os.Exit(1)
	}

	if err := (&controller.DiscoveryReconciler{
		Client:   mgr.GetClient(),
		Engine:   discovery.NewEngine(),
		Interval: controller.DefaultDiscoveryInterval,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "DiscoveryReconciler")
		os.Exit(1)
	}

	if err := (&controller.FrameworkReconciler{
		Client:    mgr.GetClient(),
		Crosswalk: crosswalkResolver,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "FrameworkReconciler")
		os.Exit(1)
	}

	setupLog.Info("starting sidereal controller manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
