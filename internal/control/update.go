package control

// UpdateStatus describes the most recent remote self-update operation.
type UpdateStatus struct {
	Running   bool   `json:"running"`
	Message   string `json:"message,omitempty"`
	LastError string `json:"last_error,omitempty"`
	Channel   string `json:"channel,omitempty"`
}

// UpdateChannel is the only branch selection accepted by the updater.
type UpdateChannel string

const (
	ChannelStable UpdateChannel = "stable"
	ChannelDev    UpdateChannel = "dev"
)

func ValidUpdateChannel(ch string) bool {
	return ch == string(ChannelStable) || ch == string(ChannelDev)
}

// UpdateController starts a controlled update of the local blipd binary.
type UpdateController interface {
	StartUpdate(channel string) error
	UpdateStatus() UpdateStatus
}
