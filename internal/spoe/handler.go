// Package spoe adapts HAProxy SPOE messages to the engine.
package spoe

import (
	"context"
	"log/slog"
	"net/netip"
	"strings"

	"github.com/dropmorepackets/haproxy-go/pkg/encoding"
	"github.com/orcinustools/bima/internal/engine"
	"github.com/orcinustools/bima/internal/fingerprint"
)

type Handler struct {
	Engine *engine.Engine
}

// HandleSPOE handles one SPOE message. Byte slices from the scanner are only
// valid during this call, so everything is copied into Go strings.
func (h *Handler) HandleSPOE(ctx context.Context, w *encoding.ActionWriter, m *encoding.Message) {
	switch string(m.NameBytes()) {
	case "check-request":
		h.request(w, m)
	case "check-response":
		h.response(m)
	}
}

func (h *Handler) request(w *encoding.ActionWriter, m *encoding.Message) {
	r := &engine.Request{}
	var rawHeaders string
	var tlsVer int
	var ciphers, exts, curves, ecpf []byte
	k := encoding.AcquireKVEntry()
	defer encoding.ReleaseKVEntry(k)
	for m.KV.Next(k) {
		switch {
		case k.NameEquals("id"):
			r.ID = string(k.ValueBytes())
		case k.NameEquals("src"):
			r.IP = addr(k)
		case k.NameEquals("method"):
			r.Method = string(k.ValueBytes())
		case k.NameEquals("path"):
			r.Path = string(k.ValueBytes())
		case k.NameEquals("query"):
			r.Query = string(k.ValueBytes())
		case k.NameEquals("ver"):
			r.Version = string(k.ValueBytes())
		case k.NameEquals("headers"):
			rawHeaders = string(k.ValueBytes())
		case k.NameEquals("body"):
			r.Body = append([]byte(nil), k.ValueBytes()...)
		case k.NameEquals("tls_ver"):
			tlsVer = int(k.ValueInt())
		case k.NameEquals("tls_ciphers"):
			ciphers = append([]byte(nil), k.ValueBytes()...)
		case k.NameEquals("tls_exts"):
			exts = append([]byte(nil), k.ValueBytes()...)
		case k.NameEquals("tls_curves"):
			curves = append([]byte(nil), k.ValueBytes()...)
		case k.NameEquals("tls_ecpf"):
			ecpf = append([]byte(nil), k.ValueBytes()...)
		}
	}
	if err := m.KV.Error(); err != nil {
		slog.Error("spoe decode", "err", err)
		return
	}
	r.Headers = parseHeaders(rawHeaders)
	r.JA3, _ = fingerprint.JA3(tlsVer, ciphers, exts, curves, ecpf)
	v := h.Engine.OnRequest(r)
	if v.FP != "" {
		_ = w.SetString(encoding.VarScopeTransaction, "fp", v.FP)
	}
	_ = w.SetString(encoding.VarScopeTransaction, "action", string(v.Action))
	_ = w.SetInt64(encoding.VarScopeTransaction, "score", int64(v.Score))
	if v.RuleID != "" {
		_ = w.SetString(encoding.VarScopeTransaction, "rule", v.RuleID)
	}
}

func (h *Handler) response(m *encoding.Message) {
	var (
		id, method, path, fp string
		ip                   netip.Addr
		status               int
	)
	k := encoding.AcquireKVEntry()
	defer encoding.ReleaseKVEntry(k)
	for m.KV.Next(k) {
		switch {
		case k.NameEquals("id"):
			id = string(k.ValueBytes())
		case k.NameEquals("src"):
			ip = addr(k)
		case k.NameEquals("method"):
			method = string(k.ValueBytes())
		case k.NameEquals("path"):
			path = string(k.ValueBytes())
		case k.NameEquals("status"):
			status = int(k.ValueInt())
		case k.NameEquals("fp"):
			fp = string(k.ValueBytes())
		}
	}
	if err := m.KV.Error(); err != nil {
		slog.Error("spoe decode", "err", err)
		return
	}
	if ip.IsValid() {
		h.Engine.OnResponse(id, ip, method, path, status, fp)
	}
}

func addr(k *encoding.KVEntry) netip.Addr {
	switch k.Type() {
	case encoding.DataTypeIPV4, encoding.DataTypeIPV6:
		a, ok := netip.AddrFromSlice(k.ValueBytes())
		if ok {
			return a.Unmap()
		}
	case encoding.DataTypeString:
		if a, err := netip.ParseAddr(string(k.ValueBytes())); err == nil {
			return a.Unmap()
		}
	}
	return netip.Addr{}
}

// parseHeaders parses the req.hdrs sample ("Name: value\r\n..." raw block).
func parseHeaders(raw string) [][2]string {
	var out [][2]string
	for line := range strings.SplitSeq(raw, "\n") {
		line = strings.TrimRight(line, "\r")
		name, val, ok := strings.Cut(line, ":")
		if !ok || name == "" || strings.ContainsAny(name, " \t") {
			continue
		}
		out = append(out, [2]string{name, strings.TrimSpace(val)})
	}
	return out
}
