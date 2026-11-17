package k8s

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/chxmxii/kollektor/internal/events"
)

const containerIDIndex = "containerID"

// PodCache watches pods scheduled on a single node and indexes them by
// container ID.
type PodCache struct {
	informer cache.SharedIndexInformer
	log      *slog.Logger
}

func NewPodCache(cs kubernetes.Interface, nodeName string, log *slog.Logger) (*PodCache, error) {
	if nodeName == "" {
		return nil, fmt.Errorf("node name is required to scope the pod watch")
	}
	factory := informers.NewSharedInformerFactoryWithOptions(cs, 10*time.Minute,
		informers.WithTweakListOptions(func(o *metav1.ListOptions) {
			o.FieldSelector = fields.OneTermEqualSelector("spec.nodeName", nodeName).String()
		}),
	)
	inf := factory.Core().V1().Pods().Informer()
	if err := inf.AddIndexers(cache.Indexers{containerIDIndex: indexByContainerID}); err != nil {
		return nil, err
	}
	return &PodCache{informer: inf, log: log.With("component", "podcache")}, nil
}

// Start runs the informer and blocks until the initial list is synced.
func (c *PodCache) Start(ctx context.Context) error {
	go c.informer.Run(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), c.informer.HasSynced) {
		return fmt.Errorf("pod cache did not sync")
	}
	c.log.Info("pod cache synced", "pods", len(c.informer.GetStore().ListKeys()))
	return nil
}

// ByContainerID returns the pod and container for a bare (runtime-prefix
// stripped) container ID.
func (c *PodCache) ByContainerID(id string) *events.PodRef {
	objs, err := c.informer.GetIndexer().ByIndex(containerIDIndex, id)
	if err != nil || len(objs) == 0 {
		return nil
	}
	pod := objs[0].(*corev1.Pod)
	for _, st := range allStatuses(pod) {
		if stripRuntime(st.ContainerID) == id {
			return &events.PodRef{
				Namespace:   pod.Namespace,
				Name:        pod.Name,
				UID:         string(pod.UID),
				Container:   st.Name,
				ContainerID: id,
			}
		}
	}
	return nil
}

func indexByContainerID(obj any) ([]string, error) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return nil, nil
	}
	var ids []string
	for _, st := range allStatuses(pod) {
		if id := stripRuntime(st.ContainerID); id != "" {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

func allStatuses(pod *corev1.Pod) []corev1.ContainerStatus {
	s := make([]corev1.ContainerStatus, 0,
		len(pod.Status.InitContainerStatuses)+len(pod.Status.ContainerStatuses)+len(pod.Status.EphemeralContainerStatuses))
	s = append(s, pod.Status.InitContainerStatuses...)
	s = append(s, pod.Status.ContainerStatuses...)
	s = append(s, pod.Status.EphemeralContainerStatuses...)
	return s
}

// stripRuntime turns "containerd://abc..." into "abc...".
func stripRuntime(id string) string {
	if _, after, ok := strings.Cut(id, "://"); ok {
		return after
	}
	return id
}
