package alert

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/orcinustools/bima/internal/detect"
)

type slowRecorder struct {
	mu  sync.Mutex
	got []string
}

func (s *slowRecorder) Name() string { return "rec" }
func (s *slowRecorder) SendEvent(_ context.Context, e Event) error {
	if e.Action == "block" {
		time.Sleep(50 * time.Millisecond) // first send is slow; must still arrive first
	}
	s.mu.Lock()
	s.got = append(s.got, e.Action)
	s.mu.Unlock()
	return nil
}
func (s *slowRecorder) SendDigest(context.Context, Digest) error { return nil }

func TestDeliveryOrderPreserved(t *testing.T) {
	r := &slowRecorder{}
	a := New("t", time.Minute, time.Minute, r)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Run(ctx)
	a.Emit(Event{Severity: detect.Critical, Category: "rce", IP: "1.2.3.4", Action: "block"})
	a.Emit(Event{Severity: detect.Critical, Category: "rce", IP: "1.2.3.4", Action: "ban 10m + block"})
	time.Sleep(300 * time.Millisecond)
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.got) != 2 || r.got[0] != "block" || r.got[1] != "ban 10m + block" {
		t.Fatalf("order not preserved: %v", r.got)
	}
}
