package embeddable

import "embed"

//go:embed output/*
var BPFObject embed.FS
