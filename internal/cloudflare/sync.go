package cloudflare

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// CommentPrefix marks list items owned by Bima; other items are never touched.
const CommentPrefix = "bima"

// Syncer mirrors Bima's active bans into a Cloudflare IP list, so banned
// clients are stopped at Cloudflare's edge (rule "ip.src in $<list>").
// It reconciles: missing bans are added, expired/lifted ones removed. Several
// agents sharing Redis may run it concurrently; the operations are idempotent.
type Syncer struct {
	c        *Client
	account  string
	listName string
	bans     func() map[string]time.Time
	interval time.Duration
	kick     chan struct{}

	mu     sync.Mutex
	listID string

	Syncs, Errors  atomic.Uint64
	Added, Removed atomic.Uint64
	Items          atomic.Int64
	LastErr        atomic.Value // string
}

func NewSyncer(c *Client, account, listName string, interval time.Duration, bans func() map[string]time.Time) *Syncer {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &Syncer{c: c, account: account, listName: listName, bans: bans, interval: interval, kick: make(chan struct{}, 1)}
}

// Kick requests a sync soon (after a ban/unban).
func (s *Syncer) Kick() {
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

func (s *Syncer) Run(ctx context.Context) {
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		c, cancel := context.WithTimeout(ctx, time.Minute)
		if err := s.SyncOnce(c); err != nil && ctx.Err() == nil {
			slog.Warn("cloudflare ban sync failed", "err", err)
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.kick:
			// coalesce bursts of bans into one API round
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
		}
	}
}

// ListKey is the list entry for a banned address: IPv4 as is, IPv6 as its
// /64 (Cloudflare lists take IPv6 prefixes /12../64; a client owns a /64).
// ok=false for addresses that must not go to an edge list (private etc.).
func ListKey(ip string) (string, bool) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return "", false
	}
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsPrivate() || netip.MustParsePrefix("100.64.0.0/10").Contains(a) {
		return "", false
	}
	if a.Is4() {
		return a.String(), true
	}
	p, _ := a.Prefix(64)
	return p.String(), true
}

func normKey(s string) string {
	if p, err := netip.ParsePrefix(s); err == nil {
		if p.Addr().Is4() && p.Bits() == 32 {
			return p.Addr().String()
		}
		return p.Masked().String()
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap().String()
	}
	return s
}

func (s *Syncer) list(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listID != "" {
		return s.listID, nil
	}
	l, created, err := s.c.EnsureList(ctx, s.account, s.listName)
	if err != nil {
		return "", err
	}
	if created {
		slog.Info("cloudflare ip list created", "list", s.listName, "id", l.ID)
	}
	s.listID = l.ID
	return l.ID, nil
}

// SyncOnce reconciles the list with the current bans.
func (s *Syncer) SyncOnce(ctx context.Context) error {
	err := s.sync(ctx)
	s.Syncs.Add(1)
	if err != nil {
		s.Errors.Add(1)
		s.LastErr.Store(err.Error())
		if NotFound(err) {
			s.mu.Lock()
			s.listID = "" // list deleted on Cloudflare's side: recreate next time
			s.mu.Unlock()
		}
		return err
	}
	s.LastErr.Store("")
	return nil
}

func (s *Syncer) sync(ctx context.Context) error {
	id, err := s.list(ctx)
	if err != nil {
		return fmt.Errorf("list %s: %w", s.listName, err)
	}
	want := map[string]time.Time{}
	for ip, until := range s.bans() {
		if k, ok := ListKey(ip); ok && until.After(want[k]) {
			want[k] = until
		}
	}
	items, err := s.c.ListItems(ctx, s.account, id)
	if err != nil {
		return err
	}
	have := map[string]bool{}
	var stale []string
	for _, it := range items {
		k := normKey(it.IP)
		if !strings.HasPrefix(it.Comment, CommentPrefix) {
			have[k] = true // somebody else's entry: blocks anyway, leave it alone
			continue
		}
		if _, ok := want[k]; ok && !have[k] {
			have[k] = true
			continue
		}
		stale = append(stale, it.ID) // lifted, expired or duplicate
	}
	var add []ListItem
	for k, until := range want {
		if !have[k] {
			add = append(add, ListItem{IP: k, Comment: CommentPrefix + " ban until " + until.UTC().Format(time.RFC3339)})
		}
	}
	if err := s.c.AddItems(ctx, s.account, id, add); err != nil {
		return fmt.Errorf("add %d items: %w", len(add), err)
	}
	if err := s.c.DeleteItems(ctx, s.account, id, stale); err != nil {
		return fmt.Errorf("delete %d items: %w", len(stale), err)
	}
	s.Added.Add(uint64(len(add)))
	s.Removed.Add(uint64(len(stale)))
	s.Items.Store(int64(len(items) + len(add) - len(stale)))
	if len(add)+len(stale) > 0 {
		slog.Info("cloudflare ban list synced", "list", s.listName, "added", len(add), "removed", len(stale))
	}
	return nil
}
