// Copyright 2022 The Swarm Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/ethersphere/bee/pkg/jsonhttp"
	"github.com/gorilla/mux"
	"resenje.org/web"
)

type proxy struct {
	port         int
	scheme, host string
	router       *mux.Router
	auth         *authenticator
	client       *http.Client
}

func (app *proxy) init() {
	router := mux.NewRouter()
	router.NotFoundHandler = http.HandlerFunc(jsonhttp.NotFoundHandler)
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

	router.MatcherFunc(func(r *http.Request, rm *mux.RouteMatch) bool {
		match, err := regexp.MatchString("/*", r.URL.Path)
		if err != nil {
			log.Println("error regex matching", err)
		}
		return match
	}).HandlerFunc(app.forwardHandler)

	app.router = router
	app.client = &http.Client{
		// TODO Transport: initTransport(),
	}
}

func (app *proxy) run() {
	log.Println("starting on port", app.port)
	log.Fatal(http.ListenAndServe(":"+strconv.Itoa(app.port), app.router))
}

func (app *proxy) shutdown() {
	log.Println("shutting down")
	app.client.CloseIdleConnections()
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

func (a *proxy) forwardHandler(w http.ResponseWriter, req *http.Request) {
	log.Println(req.URL.Path)

	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	req.Body = ioutil.NopCloser(bytes.NewReader(body))

	url := fmt.Sprintf("%s://%s%s", a.scheme, a.host, req.RequestURI)

	proxyReq, err := http.NewRequest(req.Method, url, bytes.NewReader(body))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	proxyReq.Header = make(http.Header)
	for h, val := range req.Header {
		proxyReq.Header[h] = val
	}

	resp, err := a.client.Do(proxyReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, hvv := range req.Header {
		for _, hv := range hvv {
			w.Header().Add(k, hv)
		}
	}

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}
