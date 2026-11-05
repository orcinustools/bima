package engine

import "testing"

func benchReq() *Request {
	return req("GET", "/api/users?id=7&q=hello", map[string]string{"Cookie": "session=abc; theme=dark", "Referer": "https://app.test/x"}, "")
}

func BenchmarkSignaturesOnly(b *testing.B) {
	e := newEngine(&testing.T{}, false)
	r := benchReq()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.OnRequest(r)
	}
}

func BenchmarkWithCRS(b *testing.B) {
	e := newEngine(&testing.T{}, true)
	r := benchReq()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.OnRequest(r)
	}
}

func BenchmarkWithCRSParallel(b *testing.B) {
	e := newEngine(&testing.T{}, true)
	b.RunParallel(func(pb *testing.PB) {
		r := benchReq()
		for pb.Next() {
			e.OnRequest(r)
		}
	})
}
