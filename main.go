package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/gorilla/securecookie"

	"github.com/go-yaml/yaml"
)

var config struct {
	PublisherKey string `yaml:"publisherKey"`
	AppID        string `yaml:"appID"`
	Keys         []struct {
		HashKey  string `yaml:"hashKey"`
		BlockKey string `yaml:"blockKey"`
	} `yaml:"keys"`
	SkipAuthRegex string `yaml:"skipAuthRegex"`
	Store         struct {
		Type       string
		Filesystem struct {
			Path string `yaml:"path"`
		} `yaml:"filesystem"`
	} `yaml:"store"`
}

var skipAuthRegex *regexp.Regexp

var (
	listenAddr = flag.String("listen", ":8080", "address to listen on")
	configFile = flag.String("config", "config.yaml", "config file")
)

var codecs []securecookie.Codec
var store interface {
	Get(fpath string) (http.File, error)
}

func main() {
	flag.Parse()

	cf, err := os.Open(*configFile)
	check(err)
	defer cf.Close()

	err = yaml.NewDecoder(cf).Decode(&config)
	check(err)

	if len(config.PublisherKey) == 0 {
		fatal("publisherKey missing")
	}

	if len(config.AppID) == 0 {
		fatal("appID missing")
	}

	if len(config.Keys) == 0 {
		fatal("keys missing")
	}

	if len(config.Store.Type) == 0 {
		fatal("store.type missing")
	}

	var keys [][]byte
	for i, k := range config.Keys {
		hashKey, err := hex.DecodeString(k.HashKey)
		if len(k.HashKey) != 64 || err != nil {
			fatal("key %d hashKey must be 32 hex encoded bytes", i)
		}

		blockKey, err := hex.DecodeString(k.BlockKey)
		if len(k.BlockKey) != 64 || err != nil {
			fatal("key %d blockKey must be 32 hex encoded bytes", i)
		}

		keys = append(keys, hashKey, blockKey)
	}
	codecs = securecookie.CodecsFromPairs(keys...)

	if len(config.SkipAuthRegex) > 0 {
		skipAuthRegex, err = regexp.Compile(config.SkipAuthRegex)
		check(err)
	}

	switch config.Store.Type {
	case "filesystem":
		store = &filesystem{
			path: config.Store.Filesystem.Path,
		}
	default:
		fatal("invalid store type: %s", config.Store.Type)
	}

	r := chi.NewRouter()
	// A good base middleware stack
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.HandleFunc("/get-token", tokenHandler)
	r.Get("/*", download)
	r.Head("/*", download)

	http.ListenAndServe(*listenAddr, r)
}

func download(w http.ResponseWriter, r *http.Request) {
	fpath := path.Clean(r.URL.Path[1:])
	token := r.URL.Query().Get("token")

	if skipAuthRegex == nil || !skipAuthRegex.MatchString(fpath) {
		if len(token) == 0 {
			http.Error(w, "missing token", http.StatusUnauthorized)
			return
		}

		var info UserInfo
		err := securecookie.DecodeMulti("user-info", token, &info, codecs...)
		if err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		hasGame, err := userHasGame(&info)
		if err != nil {
			log.Printf("userHasGame: %v", err)
			http.Error(w, "something bad happened", http.StatusInternalServerError)
		}
		if !hasGame {
			http.Error(w, "you do not own the game", http.StatusUnauthorized)
			return
		}
	}

	if strings.HasPrefix(fpath, "..") {
		http.NotFound(w, r)
		return
	}

	name := path.Base(fpath)

	file, err := store.Get(fpath)
	if err != nil {
		log.Printf("store.Get: %v", err)
		http.Error(w, "something bad happened", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		log.Printf("file.Stat: %v", err)
		http.Error(w, "something bad happened", http.StatusInternalServerError)
		return
	}

	http.ServeContent(w, r, name, stat.ModTime(), file)
}

func check(err error) {
	if err == nil {
		return
	}

	fatal("%v", err)
}

func fatal(fmsg string, v ...interface{}) {
	fmt.Fprintf(os.Stderr, "error: "+fmsg+"\n", v...)
	os.Exit(1)
}
