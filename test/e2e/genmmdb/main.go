// genmmdb writes tiny GeoLite2-compatible Country and ASN databases for the
// documentation/test IP ranges used by the e2e suite.
package main

import (
	"log"
	"net"
	"os"
	"path/filepath"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

type netInfo struct {
	cidr, country, org string
	asn                uint32
}

var nets = []netInfo{
	{"203.0.113.0/24", "ID", "TEST-NET-3 HOSTING", 64500},
	{"192.0.2.0/24", "NL", "EVIL-SCANNER-NET", 64501},
	{"198.51.100.0/24", "ID", "CUSTOMER-ISP", 64502},
	{"10.200.0.0/16", "ID", "OFFICE-NET", 64503},
}

func main() {
	out := "geo"
	if len(os.Args) > 1 {
		out = os.Args[1]
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		log.Fatal(err)
	}
	write(filepath.Join(out, "country.mmdb"), "GeoLite2-Country", func(n netInfo) mmdbtype.Map {
		return mmdbtype.Map{"country": mmdbtype.Map{"iso_code": mmdbtype.String(n.country)}}
	})
	write(filepath.Join(out, "asn.mmdb"), "GeoLite2-ASN", func(n netInfo) mmdbtype.Map {
		return mmdbtype.Map{"autonomous_system_number": mmdbtype.Uint32(n.asn), "autonomous_system_organization": mmdbtype.String(n.org)}
	})
}

func write(path, dbType string, rec func(netInfo) mmdbtype.Map) {
	t, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: dbType, RecordSize: 24, IncludeReservedNetworks: true})
	if err != nil {
		log.Fatal(err)
	}
	for _, n := range nets {
		_, ipn, _ := net.ParseCIDR(n.cidr)
		if err := t.Insert(ipn, rec(n)); err != nil {
			log.Fatal(err)
		}
	}
	f, err := os.Create(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	if _, err := t.WriteTo(f); err != nil {
		log.Fatal(err)
	}
	log.Printf("wrote %s", path)
}
