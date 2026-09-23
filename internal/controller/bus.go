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

// maxESSSubscribers caps concurrent /api/events SSE streams so browsers that
// never close EventSource connections cannot exhaust the controller.
const maxESSSubscribers = 100

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

// TrySubscribe is Subscribe with a subscriber cap: it returns ok=false when
// maxESSSubscribers streams are already open, so the handler can answer 429.
func (b *Bus) TrySubscribe() (ch chan Event, backlog []Event, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.subs) >= maxESSSubscribers {
		return nil, nil, false
	}
	ch = make(chan Event, 64)
	b.subs[ch] = struct{}{}
	backlog = make([]Event, len(b.buffer))
	copy(backlog, b.buffer)
	return ch, backlog, true
}

// SubscriberCount returns the number of live SSE subscribers.
func (b *Bus) SubscriberCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.subs)
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

// Publish broadcasts an event and appends it to the ring buffer. Sends hold
// the lock (non-blocking via select/default) so Unsubscribe cannot close a
// channel mid-send. The buffer is a true ring (no ever-growing backing array
// retained by slicing).
func (b *Bus) Publish(e Event) {
	// ponytail: SSE clients never render stats/health (and JSON.parse of a
	// full StatsResponse costs ~500ms on the main thread); strip here so no
	// publisher can bloat the stream or the backlog.
	e.Stats, e.Health = nil, nil
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.buffer) < b.cap {
		b.buffer = append(b.buffer, e)
	} else {
		copy(b.buffer, b.buffer[1:])
		b.buffer[len(b.buffer)-1] = e
	}
	for ch := range b.subs {
		select {
		case ch <- e:
		default:
		}
	}
}

// Recent returns the buffered events (oldest first).
func (b *Bus) Recent() []Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Event, len(b.buffer))
	copy(out, b.buffer)
	return out
}
