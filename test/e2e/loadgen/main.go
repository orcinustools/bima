// loadgen sends a realistic benign traffic corpus (or a fixed request) through
// HAProxy, rotating client IPs via X-Forwarded-For, and reports latency
// percentiles and status codes. Used for false-positive measurement (shadow
// mode) and latency overhead (with vs. without Bima).
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type req struct {
	method, path, ctype string
	body                []byte
	hdr                 map[string]string
	kind                string
}

var searches = []string{"kopi susu gula aren", "select a gift for mom", "drop shipping jakarta", "union jack t-shirt", "where to buy cat food",
	"how to cat a file in linux", "ebook 'belajar golang' pdf", "harga <100rb", "promo 12.12 & flash sale", "rm -rf node_modules tips",
	"kelas online: UI/UX (pemula)", "sepatu size 42; warna hitam", "script writing course", "order by price desc", "ls vs dir windows",
	"apa itu ${variable} di bash?", "100% cotton", "tiket konser (VIP) - 2 orang", "resep nasi goreng | mudah", "C:\\Program Files help"}

var richText = []string{
	"<p>Kelas <b>UI/UX</b> untuk pemula. Dapatkan <i>sertifikat</i>!</p>",
	"<p>Lihat <a href=\"https://example.com/promo\">promo kami</a> &amp; diskon 50%.</p>",
	"<h2>Modul</h2><ul><li>Intro</li><li>Wireframe</li></ul><img src=\"https://cdn.example.com/a.png\" alt=\"cover\">",
	"<p>Ebook \"Belajar Go\" — 300 halaman; cocok untuk backend developer.</p>",
	"<blockquote>Best course ever!</blockquote><p>Rating 5/5</p>",
}

var notes = []string{"Meeting jam 10; bawa laptop & charger", "TODO: fix bug #123 | deploy Senin", "Alamat: Jl. Sudirman No. 5; RT 01/RW 02",
	"Harga 10*5=50, diskon (20%)", "Use `go test ./...` before pushing", "email me at budi@example.com :)", "1; 2; 3; selesai",
	"Catatan: jangan lupa backup DB sebelum migrate", "Link: https://mayar.id/pricing?ref=abc&utm_source=ig", "A & B | C > D"}

func randStr(r *rand.Rand, n int) string {
	const a = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
	b := make([]byte, n)
	for i := range b {
		b[i] = a[r.IntN(len(a))]
	}
	return string(b)
}

func corpus(r *rand.Rand) req {
	switch k := r.IntN(14); k {
	case 0:
		return req{method: "GET", path: "/", kind: "home"}
	case 1:
		return req{method: "GET", path: fmt.Sprintf("/products?page=%d&sort=%s&cat=%s", r.IntN(20)+1, []string{"price_asc", "newest", "popular"}[r.IntN(3)], url.QueryEscape("ebook & kelas")), kind: "list"}
	case 2:
		return req{method: "GET", path: "/search?q=" + url.QueryEscape(searches[r.IntN(len(searches))]), kind: "search"}
	case 3:
		return req{method: "GET", path: fmt.Sprintf("/api/users/%d", r.IntN(900)+1), kind: "api-get"}
	case 4:
		body, _ := json.Marshal(map[string]any{"name": "Kelas Kopi's Blend #" + fmt.Sprint(r.IntN(99)), "price": r.IntN(500000), "description": richText[r.IntN(len(richText))], "tags": []string{"kopi", "kelas"}})
		return req{method: "POST", path: "/api/products", ctype: "application/json", body: body, kind: "product-richtext"}
	case 5:
		v := url.Values{"email": {"user" + fmt.Sprint(r.IntN(1000)) + "@mail.com"}, "password": {randStr(r, 14)}}
		return req{method: "POST", path: "/login", ctype: "application/x-www-form-urlencoded", body: []byte(v.Encode()), kind: "login"}
	case 6:
		body, _ := json.Marshal(map[string]any{"title": "note", "body": notes[r.IntN(len(notes))]})
		return req{method: "POST", path: "/api/notes", ctype: "application/json", body: body, kind: "notes"}
	case 7:
		body, _ := json.Marshal(map[string]any{"address": "Jl. Gatot Subroto Kav. 52; Lt. 3 (belakang)", "phone": "+62 812-3456-7890", "items": []map[string]any{{"id": r.IntN(100), "qty": 2}}, "note": "Tolong dibungkus rapi & cepat"})
		return req{method: "POST", path: "/api/checkout", ctype: "application/json", body: body, kind: "checkout"}
	case 8:
		sig := make([]byte, 64)
		for i := range sig {
			sig[i] = byte(r.IntN(256))
		}
		payload := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(`{"event":"payment.success","amount":%d,"customer":"Budi"}`, r.IntN(1e6))))
		body, _ := json.Marshal(map[string]any{"data": payload, "signature": base64.StdEncoding.EncodeToString(sig), "ts": time.Now().Unix()})
		return req{method: "POST", path: "/api/webhooks/payment", ctype: "application/json", body: body, hdr: map[string]string{"X-Signature": base64.StdEncoding.EncodeToString(sig)}, kind: "webhook-b64"}
	case 9:
		var b bytes.Buffer
		w := multipart.NewWriter(&b)
		fw, _ := w.CreateFormFile("avatar", fmt.Sprintf("foto profil %d.jpg", r.IntN(9)))
		fw.Write([]byte("\xff\xd8\xff\xe0JFIF fake jpeg data"))
		w.WriteField("caption", "Liburan ke Bali (2026) — seru!")
		w.Close()
		return req{method: "POST", path: "/upload", ctype: w.FormDataContentType(), body: b.Bytes(), kind: "upload"}
	case 10:
		return req{method: "GET", path: "/api/profile", hdr: map[string]string{"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"sub":"%d","name":"Budi"}`, r.IntN(1e5)))) + ".sig" + randStr(r, 10)[:5], "Cookie": "session=" + randStr(r, 24)[:20] + "; theme=dark; _ga=GA1.2.123.456"}, kind: "auth-api"}
	case 11:
		return req{method: "GET", path: []string{"/static/app.js", "/static/style.css"}[r.IntN(2)] + "?v=" + fmt.Sprint(r.IntN(100)), kind: "static"}
	case 12:
		body, _ := json.Marshal(map[string]any{"events": []map[string]any{{"type": "click", "selector": "div.card > a[href='/products']", "ts": time.Now().UnixMilli()}, {"type": "scroll", "y": r.IntN(4000)}}})
		return req{method: "POST", path: "/api/events", ctype: "application/json", body: body, kind: "analytics"}
	default:
		body, _ := json.Marshal(map[string]any{"bio": "Saya developer; suka kopi & coding (Go, Python). Cek https://github.com/budi?tab=repos", "website": "https://budi.dev/?a=1&b=2"})
		return req{method: "PUT", path: "/api/profile", ctype: "application/json", body: body, kind: "profile"}
	}
}

type result struct {
	kind   string
	status int
	dur    time.Duration
	action string
}

func run(target string, n, c, ipPool int, fixed string, seed uint64, ua string) []result {
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: c * 2}}
	jobs := make(chan int)
	res := make([]result, n)
	var wg sync.WaitGroup
	for w := 0; w < c; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			r := rand.New(rand.NewPCG(seed, uint64(w)))
			for i := range jobs {
				var q req
				if fixed != "" {
					q = req{method: "GET", path: fixed, kind: "fixed"}
				} else {
					q = corpus(r)
				}
				hr, _ := http.NewRequest(q.method, target+q.path, bytes.NewReader(q.body))
				if q.ctype != "" {
					hr.Header.Set("Content-Type", q.ctype)
				}
				hr.Header.Set("User-Agent", ua)
				hr.Header.Set("Accept", "text/html,application/json;q=0.9,*/*;q=0.8")
				hr.Header.Set("Accept-Language", "id-ID,id;q=0.9,en;q=0.8")
				for k, v := range q.hdr {
					hr.Header.Set(k, v)
				}
				hr.Header.Set("X-Forwarded-For", fmt.Sprintf("198.18.%d.%d", (i%ipPool)/250, (i%ipPool)%250+1))
				t := time.Now()
				resp, err := client.Do(hr)
				d := time.Since(t)
				st := 0
				act := ""
				if err == nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					st = resp.StatusCode
					act = resp.Header.Get("X-Bima-Action")
				}
				res[i] = result{q.kind, st, d, act}
			}
		}(w)
	}
	for i := 0; i < n; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return res
}

func pct(ds []time.Duration, p float64) float64 {
	if len(ds) == 0 {
		return 0
	}
	i := int(float64(len(ds)-1) * p)
	return float64(ds[i].Microseconds()) / 1000
}

type summary struct {
	Target  string         `json:"target"`
	N       int            `json:"n"`
	P50     float64        `json:"p50_ms"`
	P95     float64        `json:"p95_ms"`
	P99     float64        `json:"p99_ms"`
	Status  map[string]int `json:"status"`
	Actions map[string]int `json:"actions"`
	// requests per corpus kind that were not 2xx/401 (=potential FPs)
	Blocked map[string]int `json:"blocked_by_kind"`
}

func summarize(target string, rs []result) summary {
	s := summary{Target: target, N: len(rs), Status: map[string]int{}, Actions: map[string]int{}, Blocked: map[string]int{}}
	var ds []time.Duration
	for _, r := range rs {
		ds = append(ds, r.dur)
		s.Status[fmt.Sprint(r.status)]++
		if r.action != "" {
			s.Actions[r.action]++
		}
		if r.status == 403 || r.status == 429 || r.status == 0 {
			s.Blocked[r.kind]++
		}
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	s.P50, s.P95, s.P99 = pct(ds, .50), pct(ds, .95), pct(ds, .99)
	return s
}

func main() {
	target := flag.String("url", "http://127.0.0.1:18080", "target base URL")
	bypass := flag.String("bypass", "", "optional bypass URL (same app without Bima) for comparison")
	n := flag.Int("n", 2000, "requests")
	c := flag.Int("c", 20, "concurrency")
	pool := flag.Int("ips", 1000, "distinct client IPs (X-Forwarded-For 198.18.0.0/15)")
	fixed := flag.String("fixed", "", "fixed path instead of the benign corpus")
	ua := flag.String("ua", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36", "User-Agent")
	flag.Parse()

	var out []summary
	rounds := 1
	if *bypass != "" {
		rounds = 3 // interleave to reduce noise on shared hosts
	}
	agg := map[string][]result{}
	for i := 0; i < rounds; i++ {
		agg[*target] = append(agg[*target], run(*target, *n/rounds, *c, *pool, *fixed, uint64(i+1), *ua)...)
		if *bypass != "" {
			agg[*bypass] = append(agg[*bypass], run(*bypass, *n/rounds, *c, *pool, *fixed, uint64(i+1), *ua)...)
		}
	}
	out = append(out, summarize(*target, agg[*target]))
	if *bypass != "" {
		out = append(out, summarize(*bypass, agg[*bypass]))
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(out)
	_ = strings.TrimSpace
}
