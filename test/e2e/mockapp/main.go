// mockapp is a tiny backend used by the e2e stack: known routes return 200,
// /login returns 401 for wrong credentials and everything else is 404.
package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strconv"
)

var userRoute = regexp.MustCompile(`^/api/users/(\d+)$`)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login" {
			_, _ = io.Copy(io.Discard, r.Body)
		}
		switch r.URL.Path {
		case "/", "/health", "/api/ping", "/search", "/hello", "/download", "/api/notes", "/upload", "/api/users", "/api/report", "/dashboard", "/greeting", "/index.php", "/items", "/api/run",
			"/products", "/api/products", "/api/checkout", "/api/webhooks/payment", "/api/snippets", "/api/profile", "/api/events", "/static/app.js", "/static/style.css", "/api/orders", "/checkout", "/dashboard/",
			"/api/me", "/graphql", "/api/tickets", "/api/import", "/api/settings", "/api/fetch", "/api/oauth/start", "/api/csp-report", "/api/schedule", "/api/posts", "/api/files", "/api/s3proxy", "/oauth/callback", "/login/", "/files/v1.2/report.final.tar.gz":
			fmt.Fprintf(w, "ok %s %s\n", r.Method, r.URL.Path)
			return
		case "/login":
			if r.Method == http.MethodPost && r.FormValue("password") == "correct-horse" {
				fmt.Fprintln(w, "welcome")
				return
			}
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		if m := userRoute.FindStringSubmatch(r.URL.Path); m != nil {
			id, _ := strconv.Atoi(m[1])
			if id <= 1000 {
				fmt.Fprintf(w, `{"id":%d,"name":"user%d"}`+"\n", id, id)
				return
			}
		}
		http.NotFound(w, r)
	})
	log.Println("mockapp listening on :8000")
	log.Fatal(http.ListenAndServe(":8000", nil))
}
