// Package k8s maps processes on this node to the pods/containers they run in.
package k8s

import (
	"fmt"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// NewClientset uses in-cluster config when available and falls back to the
// kubeconfig (KUBECONFIG / ~/.kube/config) for local development.
func NewClientset(kubeconfig string) (kubernetes.Interface, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		rules := clientcmd.NewDefaultClientConfigLoadingRules()
		if kubeconfig != "" {
			rules.ExplicitPath = kubeconfig
		}
		cfg, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, nil).ClientConfig()
		if err != nil {
			return nil, fmt.Errorf("building kube config: %w", err)
		}
	}
	cfg.UserAgent = "kollektor-agent"
	return kubernetes.NewForConfig(cfg)
}
