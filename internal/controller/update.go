package controller

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/twobip/BlipDNS/internal/control"
)

const updateNodeTimeout = 10 * time.Minute

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
		f.setUpdateCurrent(node.id)
		if err := f.updateOne(node.inst, channel); err != nil {
			f.finishUpdate(node.id, "failed: "+err.Error(), err.Error())
			return
		}
		f.finishUpdate(node.id, "updated", "")
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
