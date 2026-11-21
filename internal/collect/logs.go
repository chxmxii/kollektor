package collect

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"sync"

	corev1 "k8s.io/api/core/v1"
)

// kubeletNoLogsPrefix starts the body the kubelet returns instead of a log
// that no longer exists on the node.
const kubeletNoLogsPrefix = "unable to retrieve container logs for "

type logJob struct {
	ns, pod, container string
	previous           bool
}

// collectLogs fetches the current log of every started container, plus the
// previous instance's log for containers that have restarted. Failures are
// recorded in the manifest, not fatal.
func (c *collector) collectLogs(ctx context.Context) error {
	var jobs []logJob
	for _, p := range c.pods {
		for _, st := range allStatuses(&p) {
			if st.State.Running != nil || st.State.Terminated != nil {
				jobs = append(jobs, logJob{p.Namespace, p.Name, st.Name, false})
			}
			if st.LastTerminationState.Terminated != nil {
				jobs = append(jobs, logJob{p.Namespace, p.Name, st.Name, true})
			}
		}
	}
	c.log.Info("collecting logs", "streams", len(jobs))

	spool, err := os.MkdirTemp("", "kollektor-logs-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(spool)

	sem := make(chan struct{}, c.opts.Concurrency)
	var wg sync.WaitGroup
	errc := make(chan error, 1)
	for _, j := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			if err := c.fetchLog(ctx, spool, j); err != nil {
				select {
				case errc <- err:
				default:
				}
			}
		}()
	}
	wg.Wait()
	select {
	case err := <-errc:
		return err
	default:
		return ctx.Err()
	}
}

// fetchLog spools one log stream to disk first (its size is unknown up front
// and logs can be large), then copies it into the archive.
func (c *collector) fetchLog(ctx context.Context, spool string, j logJob) error {
	name := j.container + ".log"
	if j.previous {
		name = j.container + ".previous.log"
	}
	id := fmt.Sprintf("%s/%s/%s", j.ns, j.pod, name)

	opts := &corev1.PodLogOptions{Container: j.container, Previous: j.previous, Timestamps: true}
	if c.opts.LogSince > 0 {
		s := int64(c.opts.LogSince.Seconds())
		opts.SinceSeconds = &s
	}
	stream, err := c.cs.CoreV1().Pods(j.ns).GetLogs(j.pod, opts).Stream(ctx)
	if err != nil {
		c.out.RecordError("logs %s: %v", id, err)
		return nil
	}
	defer stream.Close()

	tmp, err := os.CreateTemp(spool, "log-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	size, err := io.Copy(tmp, stream)
	if err != nil {
		// Keep what we got; a truncated log is still evidence.
		c.out.RecordError("logs %s: truncated after %d bytes: %v", id, size, err)
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return err
	}
	// When the runtime has already rotated or garbage-collected the log, the
	// kubelet answers 200 with an error message as the body. Never store
	// that as if it were the container's output.
	if size < 512 {
		head, _ := io.ReadAll(tmp)
		if bytes.HasPrefix(head, []byte(kubeletNoLogsPrefix)) {
			c.out.RecordError("logs %s: %s", id, head)
			return nil
		}
		if _, err := tmp.Seek(0, io.SeekStart); err != nil {
			return err
		}
	}
	_, err = c.out.WriteFrom(path.Join("logs", id), tmp, size)
	return err
}

func allStatuses(p *corev1.Pod) []corev1.ContainerStatus {
	var s []corev1.ContainerStatus
	s = append(s, p.Status.InitContainerStatuses...)
	s = append(s, p.Status.ContainerStatuses...)
	s = append(s, p.Status.EphemeralContainerStatuses...)
	return s
}
