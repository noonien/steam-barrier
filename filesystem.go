package main

import (
	"net/http"
	"os"
	"path"
)

type filesystem struct {
	path string
}

func (fs *filesystem) Get(fpath string) (http.File, error) {
	f, err := os.Open(path.Join(fs.path, fpath))
	return f, err
}
