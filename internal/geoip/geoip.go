// Package geoip enriches IPs with country and ASN from MaxMind-format (MMDB)
// databases, e.g. GeoLite2-Country/ASN or the free DB-IP Lite databases.
package geoip

import (
	"net"
	"strconv"

	"github.com/oschwald/maxminddb-golang"
)

type Info struct {
	Country string // ISO code, e.g. "ID"
	ASN     uint
	ASOrg   string
}

func (i Info) String() string {
	s := ""
	if i.ASN != 0 {
		s = "AS" + strconv.FormatUint(uint64(i.ASN), 10)
		if i.ASOrg != "" {
			s += " " + i.ASOrg
		}
	}
	if i.Country != "" {
		if s != "" {
			s += ", "
		}
		s += i.Country
	}
	return s
}

type DB struct {
	country, asn *maxminddb.Reader
}

// Open opens the databases; either path may be empty.
func Open(countryPath, asnPath string) (*DB, error) {
	db := &DB{}
	var err error
	if countryPath != "" {
		if db.country, err = maxminddb.Open(countryPath); err != nil {
			return nil, err
		}
	}
	if asnPath != "" {
		if db.asn, err = maxminddb.Open(asnPath); err != nil {
			return nil, err
		}
	}
	return db, nil
}

func (db *DB) Lookup(ipStr string) Info {
	var info Info
	if db == nil {
		return info
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return info
	}
	if db.country != nil {
		var rec struct {
			Country struct {
				ISOCode string `maxminddb:"iso_code"`
			} `maxminddb:"country"`
		}
		if db.country.Lookup(ip, &rec) == nil {
			info.Country = rec.Country.ISOCode
		}
	}
	if db.asn != nil {
		var rec struct {
			ASN uint   `maxminddb:"autonomous_system_number"`
			Org string `maxminddb:"autonomous_system_organization"`
		}
		if db.asn.Lookup(ip, &rec) == nil {
			info.ASN, info.ASOrg = rec.ASN, rec.Org
		}
	}
	return info
}
