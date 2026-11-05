package geoip

import (
	"os"
	"testing"
)

func TestLookup(t *testing.T) {
	dir := os.Getenv("BIMA_TEST_GEO")
	if dir == "" {
		t.Skip("BIMA_TEST_GEO not set")
	}
	db, err := Open(dir+"/country.mmdb", dir+"/asn.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	if got := db.Lookup("192.0.2.7").String(); got != "AS64501 EVIL-SCANNER-NET, NL" {
		t.Fatalf("got %q", got)
	}
	if got := db.Lookup("8.8.8.8").String(); got != "" {
		t.Fatalf("unmapped got %q", got)
	}
}
