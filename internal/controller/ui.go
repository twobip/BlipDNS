package controller

import (
	"embed"
	"io/fs"
)

//go:embed all:web
var webFS embed.FS

// UI returns the embedded web dashboard filesystem (index.html, app.js, …).
func UI() fs.FS {
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		return nil
	}
	return sub
}
