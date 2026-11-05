// Package fingerprint derives client fingerprints: JA3 from the TLS
// ClientHello fields HAProxy captures, and a combined fingerprint
// (JA3 + header order + User-Agent) used to group distributed scanners.
package fingerprint

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"strings"
)

// JA3 computes the JA3 hash from HAProxy samples:
// ver = ssl_fc_protocol_hello_id, ciphers = ssl_fc_cipherlist_bin(1),
// exts = ssl_fc_extlist_bin(1), curves = ssl_fc_eclist_bin(1),
// ecpf = ssl_fc_ecformats_bin. (The "(1)" argument removes GREASE values.)
// Returns "" when not a TLS connection.
func JA3(ver int, ciphers, exts, curves, ecpf []byte) (hash, raw string) {
	if ver == 0 && len(ciphers) == 0 {
		return "", ""
	}
	var b strings.Builder
	b.WriteString(strconv.Itoa(ver))
	b.WriteByte(',')
	writeU16(&b, ciphers)
	b.WriteByte(',')
	writeU16(&b, exts)
	b.WriteByte(',')
	writeU16(&b, curves)
	b.WriteByte(',')
	for i, v := range ecpf {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(strconv.Itoa(int(v)))
	}
	raw = b.String()
	sum := md5.Sum([]byte(raw))
	return hex.EncodeToString(sum[:]), raw
}

func writeU16(b *strings.Builder, p []byte) {
	for i := 0; i+1 < len(p); i += 2 {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(strconv.Itoa(int(binary.BigEndian.Uint16(p[i:]))))
	}
}

// Client combines JA3 (may be empty), the order of request header names and
// the User-Agent into a short stable fingerprint.
func Client(ja3 string, headerNames []string, ua string) string {
	h := md5.New()
	h.Write([]byte(ja3))
	h.Write([]byte{0})
	for _, n := range headerNames {
		h.Write([]byte(strings.ToLower(n)))
		h.Write([]byte{','})
	}
	h.Write([]byte{0})
	h.Write([]byte(ua))
	return hex.EncodeToString(h.Sum(nil))[:16]
}
