// Package bima exposes files embedded into the binary: the agent skills
// (`bima skills`) and deployment templates used by `bima init`.
package bima

import "embed"

//go:embed skills deploy/bima-spoe.conf deploy/monitoring
var Assets embed.FS
