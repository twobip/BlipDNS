package controller

import "sync"

// Bus is a thread-safe broadcast hub with a bounded ring buffer of recent
// events for late-joining SSE clients.
type Bus struct {
	mu     sync.Mutex
	subs   map[chan Event]struct{}
	buffer []Event
	cap    int
}

// NewBus creates a bus retaining up to cap recent events.
func NewBus(cap int) *Bus {
	if cap <= 0 {
		cap = 500
	}
	return &Bus{
		subs:   make(map[chan Event]struct{}),
		buffer: make([]Event, 0, cap),
		cap:    cap,
	}
}

// Subscribe registers a channel and returns the recent backlog (oldest first).
func (b *Bus) Subscribe() (chan Event, []Event) {
	ch := make(chan Event, 64)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	backlog := make([]Event, len(b.buffer))
	copy(backlog, b.buffer)
	b.mu.Unlock()
	return ch, backlog
}

// Unsubscribe removes a channel.
func (b *Bus) Unsubscribe(ch chan Event) {
	b.mu.Lock()
	if _, ok := b.subs[ch]; ok {
		delete(b.subs, ch)
		close(ch)
	}
	b.mu.Unlock()
}

// Publish broadcasts an event and appends it to the ring buffer.
func (b *Bus) Publish(e Event) {
	b.mu.Lock()
	b.buffer = append(b.buffer, e)
	if len(b.buffer) > b.cap {
		b.buffer = b.buffer[len(b.buffer)-b.cap:]
	}
	for ch := range b.subs {
		select {
		case ch <- e:
		default:
		}
	}
	b.mu.Unlock()
}

// Recent returns the buffered events (oldest first).
func (b *Bus) Recent() []Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Event, len(b.buffer))
	copy(out, b.buffer)
	return out
}
