package controller

import (
	"context"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/twobip/BlipDNS/internal/control"
)

const updateNodeTimeout = 10 * time.Minute

// haFailoverWait is how long the controller pauses after degrading a node's
// VRRP priority before starting the blipd restart, giving the peer time to
// converge on the VIP (keepalived reload + 3 VRRP advertisements at 1s).
// It is a variable (not const) so tests can shorten it.
var haFailoverWait = 10 * time.Second

type UpdateJobStatus struct {
	Running    bool              `json:"running"`
	Channel    string            `json:"channel"`
	Current    string            `json:"current,omitempty"`
	Total      int               `json:"total"`
	Completed  int               `json:"completed"`
	Results    map[string]string `json:"results"`
	Error      string            `json:"error,omitempty"`
	StartedAt  time.Time         `json:"started_at"`
	FinishedAt time.Time         `json:"finished_at,omitempty"`
}

type updateNode struct {
	id   string
	inst *Instance
}

func (f *Fleet) UpdateJob() UpdateJobStatus {
	f.updateMu.Lock()
	defer f.updateMu.Unlock()
	return cloneUpdateJob(f.updateJob)
}

func cloneUpdateJob(in UpdateJobStatus) UpdateJobStatus {
	in.Results = mapsClone(in.Results)
	return in
}

func mapsClone(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (f *Fleet) StartUpdates(ctx context.Context, channel string) (UpdateJobStatus, error) {
	if !control.ValidUpdateChannel(channel) {
		return UpdateJobStatus{}, fmt.Errorf("release channel must be stable or dev")
	}

	f.mu.RLock()
	nodes := make([]updateNode, 0, len(f.instances))
	for id, inst := range f.instances {
		if inst.hasToken() {
			nodes = append(nodes, updateNode{id: id, inst: inst})
		}
	}
	f.mu.RUnlock()
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].id < nodes[j].id })

	f.updateMu.Lock()
	defer f.updateMu.Unlock()
	if f.updateJob.Running {
		return cloneUpdateJob(f.updateJob), fmt.Errorf("an instance update is already running")
	}
	f.updateJob = UpdateJobStatus{
		Running:   true,
		Channel:   channel,
		Total:     len(nodes),
		Results:   make(map[string]string, len(nodes)),
		StartedAt: time.Now(),
	}
	job := cloneUpdateJob(f.updateJob)
	go f.runUpdateJob(nodes, channel)
	return job, nil
}

func (f *Fleet) runUpdateJob(nodes []updateNode, channel string) {
	for _, node := range nodes {
		// Mark this node as the one being updated BEFORE degrading its
		// priority. This prevents the poll loop's maybePushHA from racing
		// in and re-applying the desired (full) config mid-degradation,
		// which would undo the priority reduction and prevent the peer
		// from taking over the VIP.
		f.setUpdateCurrent(node.id)

		// Lower the VRRP priority on this node so its HA peer takes over the
		// VIP while blipd is restarting. Errors are non-fatal: the HA config
		// may simply be absent, or the node may not be part of a cluster.
		if err := f.degradeHAPriority(context.Background(), node.id); err != nil {
			log.Printf("blipc: HA priority degrade for %s: %v", node.id, err)
		}

		// Give keepalived time to reload and the peer time to converge on
		// the VIP before we kill the service. Without this the blipd
		// restart could complete before the peer has taken over, causing a
		// brief traffic blackhole.
		time.Sleep(haFailoverWait)

		if err := f.updateOne(node.inst, channel); err != nil {
			f.finishUpdate(node.id, "failed: "+err.Error(), err.Error())
			// Restore priority even on failure so the peer can hand back the
			// VIP once this node is back online.
			if err := f.restoreHAPriority(context.Background(), node.id); err != nil {
				log.Printf("blipc: HA priority restore for %s: %v", node.id, err)
			}
			return
		}
		f.finishUpdate(node.id, "updated", "")

		// Restore the original priority now that the node has restarted and
		// recovered. We tolerate failure: if keepalived or the peer is
		// briefly unreachable, the poll loop's HA status poll will show the
		// degraded state and the operator can intervene or the periodic
		// convergence will correct it on the next successful push.
		if err := f.restoreHAPriority(context.Background(), node.id); err != nil {
			log.Printf("blipc: HA priority restore for %s: %v", node.id, err)
		}

		// Give keepalived time to reload and the restored node time to
		// re-claim the VIP before the next node's update begins.
		time.Sleep(haFailoverWait)
	}
	f.updateMu.Lock()
	f.updateJob.Running = false
	f.updateJob.Current = ""
	f.updateJob.FinishedAt = time.Now()
	f.updateMu.Unlock()
}

func (f *Fleet) updateOne(inst *Instance, channel string) error {
	ctx, cancel := context.WithTimeout(context.Background(), updateNodeTimeout)
	defer cancel()
	if err := inst.ctl().StartUpdate(ctx, channel); err != nil {
		return err
	}

	phase := "start" // start -> updating -> restart -> done
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		status, statusErr := inst.ctl().UpdateStatus(ctx)
		if statusErr != nil {
			switch phase {
			case "updating", "restart":
				phase = "restart"
			default:
				// Node briefly unreachable before the updater reported in:
				// keep waiting.
			}
		} else if status.Running {
			phase = "updating"
		} else if phase == "updating" || phase == "restart" {
			phase = "restart"
			if _, err := inst.ctl().Health(ctx); err == nil {
				return nil
			}
		} else if status.LastError != "" {
			return fmt.Errorf("remote updater: %s", status.LastError)
		}

		if phase == "restart" {
			if _, err := inst.ctl().Health(ctx); err == nil {
				return nil
			}
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("node did not return online within %s", updateNodeTimeout)
		case <-ticker.C:
		}
	}
}

func (f *Fleet) setUpdateCurrent(id string) {
	f.updateMu.Lock()
	f.updateJob.Current = id
	f.updateMu.Unlock()
}

func (f *Fleet) finishUpdate(id, result, failure string) {
	f.updateMu.Lock()
	f.updateJob.Results[id] = result
	if failure != "" {
		f.updateJob.Error = failure
		f.updateJob.Running = false
		f.updateJob.Current = ""
		f.updateJob.FinishedAt = time.Now()
	} else {
		f.updateJob.Completed++
	}
	f.updateMu.Unlock()
}
