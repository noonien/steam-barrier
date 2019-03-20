package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/securecookie"
	lru "github.com/hashicorp/golang-lru"
	"github.com/solovev/steam_go"
)

type UserInfo struct {
	SteamID   uint64
	CreatedAt time.Time
}

func tokenHandler(w http.ResponseWriter, r *http.Request) {
	opId := steam_go.NewOpenId(r)
	switch opId.Mode() {
	case "":
		http.Redirect(w, r, opId.AuthUrl(), 301)
	case "cancel":
		w.Write([]byte("cancelled"))
	default:
		steamID, err := opId.ValidateAndGetId()
		if err != nil {
			http.Error(w, "failed to validate openId", http.StatusInternalServerError)
			return
		}

		id, err := strconv.ParseUint(steamID, 10, 64)
		if err != nil {
			http.Error(w, "invalid user steam id", http.StatusInternalServerError)
			return
		}

		info := UserInfo{
			SteamID:   id,
			CreatedAt: time.Now(),
		}

		token, err := securecookie.EncodeMulti("user-info", info, codecs...)
		if err != nil {
			log.Printf("error while encoding user token")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		fmt.Fprintf(w, "Your token: %s", token)
	}
}

const baseURL = "https://partner.steam-api.com/ISteamUser/CheckAppOwnership/v2/"

var authCache *lru.Cache

func init() {
	var err error
	authCache, err = lru.New(1024)
	check(err)
}

func userHasGame(info *UserInfo) (bool, error) {
	if _, ok := authCache.Get(info.SteamID); ok {
		return true, nil
	}

	apiURL := fmt.Sprintf(baseURL+"key=%s&appid=%s&steamid=%d", config.PublisherKey, config.AppID, info.SteamID)

	var result struct {
		AppOwnership struct {
			Result bool `json:"bool"`
		} `json:"appownership"`
	}

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return false, err
	}

	req.Header.Set("User-Agent", "steam-barrier")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return false, errors.New("invalid response code, appID not yours?")
	}

	if result.AppOwnership.Result {
		authCache.Add(info.SteamID, true)
	}

	return result.AppOwnership.Result, nil
}
