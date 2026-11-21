// Package k8s holds Kubernetes client helpers.
package k8s

import (
	"fmt"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Target identifies the cluster kollektor talks to.
type Target struct {
	Config  *rest.Config
	Context string // kubeconfig context name, or "in-cluster"
	Server  string
}

// LoadTarget resolves a kubeconfig (KUBECONFIG / ~/.kube/config unless
// kubeconfig is set) and optional context override. When no kubeconfig is
// found it falls back to in-cluster config.
func LoadTarget(kubeconfig, context string) (*Target, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		rules.ExplicitPath = kubeconfig
	}
	cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{CurrentContext: context})

	cfg, err := cc.ClientConfig()
	if err != nil {
		if context == "" && kubeconfig == "" {
			if ic, icErr := rest.InClusterConfig(); icErr == nil {
				ic.UserAgent = "kollektor"
				return &Target{Config: ic, Context: "in-cluster", Server: ic.Host}, nil
			}
		}
		return nil, fmt.Errorf("loading kubeconfig: %w", err)
	}
	raw, err := cc.RawConfig()
	if err != nil {
		return nil, err
	}
	name := raw.CurrentContext
	if context != "" {
		name = context
	}

	cfg.UserAgent = "kollektor"
	// Deprecation warnings (e.g. v1 Endpoints) are noise for this tool.
	cfg.WarningHandler = rest.NoWarnings{}
	// Collection issues many list calls in parallel; the client-go defaults
	// (5 QPS) would make large clusters take minutes.
	cfg.QPS, cfg.Burst = 50, 100
	return &Target{Config: cfg, Context: name, Server: cfg.Host}, nil
}
