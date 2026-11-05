// Package scenarios holds the data-driven WAF test corpus (attacks, recent
// CVEs, benign traffic). It is used by the engine unit test and by the e2e
// runner (test/e2e/scenariorun) against a live HAProxy.
package scenarios

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed *.yaml
var files embed.FS

type Scenario struct {
	ID      string            `yaml:"id"`
	Cat     string            `yaml:"cat"`
	CVE     string            `yaml:"cve"`
	Desc    string            `yaml:"desc"`
	Method  string            `yaml:"m"`
	Path    string            `yaml:"p"` // raw request target (path?query), sent as-is
	Headers map[string]string `yaml:"h"`
	Body    string            `yaml:"b"`
	CT      string            `yaml:"ct"`
	Expect  string            `yaml:"x"`   // block | allow | tarpit
	Gap     string            `yaml:"gap"` // documented known gap / known FP: reported, not failed
}

func (s Scenario) PathOnly() string { p, _, _ := strings.Cut(s.Path, "?"); return p }
func (s Scenario) Query() string    { _, q, _ := strings.Cut(s.Path, "?"); return q }

// Load returns every scenario from the embedded YAML files, sorted by file then order.
func Load() ([]Scenario, error) {
	names, _ := fs.Glob(files, "*.yaml")
	sort.Strings(names)
	var out []Scenario
	seen := map[string]bool{}
	for _, n := range names {
		b, err := files.ReadFile(n)
		if err != nil {
			return nil, err
		}
		var f struct {
			Scenarios []Scenario `yaml:"scenarios"`
		}
		if err := yaml.Unmarshal(b, &f); err != nil {
			return nil, fmt.Errorf("%s: %w", n, err)
		}
		for _, s := range f.Scenarios {
			if seen[s.ID] {
				return nil, fmt.Errorf("%s: duplicate id %s", n, s.ID)
			}
			seen[s.ID] = true
			if s.Method == "" {
				s.Method = "GET"
			}
			out = append(out, s)
		}
	}
	return out, nil
}
