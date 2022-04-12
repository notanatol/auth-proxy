// Copyright 2022 The Swarm Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/ethersphere/bee/pkg/jsonhttp"
	"github.com/gorilla/mux"
	"resenje.org/web"
)

type proxy struct {
	port   int
	router *mux.Router
	auth   *authenticator
}

func (app *proxy) init() {
	router := mux.NewRouter()
	router.NotFoundHandler = http.HandlerFunc(jsonhttp.NotFoundHandler)
	router.HandleFunc("/", jsonhttp.NotFoundHandler)
	router.Handle("/auth", jsonhttp.MethodHandler{
		"POST": web.ChainHandlers(
			jsonhttp.NewMaxBodyBytesHandler(512),
			web.FinalHandlerFunc(app.authHandler),
		),
	})
	router.Handle("/refresh", jsonhttp.MethodHandler{
		"POST": web.ChainHandlers(
			jsonhttp.NewMaxBodyBytesHandler(512),
			web.FinalHandlerFunc(app.refreshHandler),
		),
	})
	app.router = router
}

func (app *proxy) run() {
	log.Println("starting on port", app.port)
	log.Fatal(http.ListenAndServe(":"+strconv.Itoa(app.port), app.router))
}

func (app *proxy) shutdown() {
	log.Println("shutting down")
}

type securityTokenRsp struct {
	Key string `json:"key"`
}

type securityTokenReq struct {
	Role   string `json:"role"`
	Expiry int    `json:"expiry"`
}

func (a *proxy) authHandler(w http.ResponseWriter, r *http.Request) {
	_, pass, ok := r.BasicAuth()

	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
		jsonhttp.Unauthorized(w, "Unauthorized")
		return
	}

	if !a.auth.Authorize(pass) {
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
		jsonhttp.Unauthorized(w, "Unauthorized")
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		jsonhttp.BadRequest(w, "Read request body")
		return
	}

	var payload securityTokenReq
	if err = json.Unmarshal(body, &payload); err != nil {
		jsonhttp.BadRequest(w, "Unmarshal json body")
		return
	}

	key, err := a.auth.GenerateKey(payload.Role, payload.Expiry)
	if errors.Is(err, errInvalidExpiry) {
		jsonhttp.BadRequest(w, "Expiry duration must be a positive number")
		return
	}
	if err != nil {
		jsonhttp.InternalServerError(w, "Error generating authorization token")
		return
	}

	jsonhttp.Created(w, securityTokenRsp{
		Key: key,
	})
}

func (a *proxy) refreshHandler(w http.ResponseWriter, r *http.Request) {
	reqToken := r.Header.Get("Authorization")
	if !strings.HasPrefix(reqToken, "Bearer ") {
		jsonhttp.Forbidden(w, "Missing bearer token")
		return
	}

	keys := strings.Split(reqToken, "Bearer ")

	if len(keys) != 2 || strings.Trim(keys[1], " ") == "" {
		jsonhttp.Forbidden(w, "Missing security token")
		return
	}

	authToken := keys[1]

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		jsonhttp.BadRequest(w, "Read request body")
		return
	}

	var payload securityTokenReq
	if err = json.Unmarshal(body, &payload); err != nil {
		jsonhttp.BadRequest(w, "Unmarshal json body")
		return
	}

	key, err := a.auth.RefreshKey(authToken, payload.Expiry)
	if errors.Is(err, errTokenExpired) {
		jsonhttp.BadRequest(w, "Token expired")
		return
	}

	if err != nil {
		log.Println(err)
		jsonhttp.InternalServerError(w, "Error refreshing authorization token")
		return
	}

	jsonhttp.Created(w, securityTokenRsp{
		Key: key,
	})
}
