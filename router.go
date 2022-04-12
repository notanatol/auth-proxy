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
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/ethersphere/bee/pkg/jsonhttp"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"resenje.org/web"
)

type proxy struct {
	port         int
	scheme, host string
	router       *mux.Router
	auth         *authenticator
	client       *http.Client
	// logger       *logrus.Logger
}

func (app *proxy) init() {
	// log := logrus.New()
	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)
	// log = log

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
			log.WithField("err", err).Error("regex matching")
		}
		return match
	}).HandlerFunc(app.forwardHandler)

	app.router = router
	app.client = &http.Client{
		// TODO Transport: initTransport(),
	}
}

func (app *proxy) run() {
	log.WithField("port", app.port).Info("starting")
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", app.port), app.router))
}

func (app *proxy) shutdown() {
	log.Warn("shutting down")
	app.client.CloseIdleConnections()
}

type securityTokenRsp struct {
	Key string `json:"key"`
}

type securityTokenReq struct {
	Role   string `json:"role"`
	Expiry int    `json:"expiry"`
}

func (app *proxy) authHandler(w http.ResponseWriter, r *http.Request) {
	_, pass, ok := r.BasicAuth()

	if !ok {
		log.Error("api: auth handler: missing basic auth")
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
		jsonhttp.Unauthorized(w, "Unauthorized")
		return
	}

	if !app.auth.Authorize(pass) {
		log.Error("api: auth handler: unauthorized")
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
		jsonhttp.Unauthorized(w, "Unauthorized")
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Debugf("api: auth handler: read request body: %v", err)
		log.WithField("err", err).Error("api: auth handler: read request body")
		jsonhttp.BadRequest(w, "Read request body")
		return
	}

	var payload securityTokenReq
	if err = json.Unmarshal(body, &payload); err != nil {
		log.Debugf("api: auth handler: unmarshal request body: %v", err)
		log.WithField("err", err).Error("api: auth handler: unmarshal request body")
		jsonhttp.BadRequest(w, "Unmarshal json body")
		return
	}

	key, err := app.auth.GenerateKey(payload.Role, payload.Expiry)
	if errors.Is(err, errInvalidExpiry) {
		log.Debugf("api: auth handler: generate key: %v", err)
		log.WithField("err", err).Error("api: auth handler: generate key")
		jsonhttp.BadRequest(w, "Expiry duration must be a positive number")
		return
	}
	if err != nil {
		log.Debugf("api: auth handler: add auth token: %v", err)
		log.WithField("err", err).Error("api: auth handler: add auth token")
		jsonhttp.InternalServerError(w, "Error generating authorization token")
		return
	}

	jsonhttp.Created(w, securityTokenRsp{
		Key: key,
	})
}

func (app *proxy) refreshHandler(w http.ResponseWriter, r *http.Request) {
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
		log.Debugf("api: auth handler: read request body: %v", err)
		log.Error("api: auth handler: read request body")
		jsonhttp.BadRequest(w, "Read request body")
		return
	}

	var payload securityTokenReq
	if err = json.Unmarshal(body, &payload); err != nil {
		log.Debugf("api: auth handler: unmarshal request body: %v", err)
		log.Error("api: auth handler: unmarshal request body")
		jsonhttp.BadRequest(w, "Unmarshal json body")
		return
	}

	key, err := app.auth.RefreshKey(authToken, payload.Expiry)
	if errors.Is(err, errTokenExpired) {
		log.Debugf("api: auth handler: refresh key: %v", err)
		log.Error("api: auth handler: refresh key")
		jsonhttp.BadRequest(w, "Token expired")
		return
	}

	if err != nil {
		log.Debugf("api: auth handler: refresh token: %v", err)
		log.Error("api: auth handler: refresh token")
		jsonhttp.InternalServerError(w, "Error refreshing authorization token")
		return
	}

	jsonhttp.Created(w, securityTokenRsp{
		Key: key,
	})
}

func (app *proxy) forwardHandler(w http.ResponseWriter, req *http.Request) {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		log.WithField("err", err).Error("read request body")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	req.Body = ioutil.NopCloser(bytes.NewReader(body))

	url := fmt.Sprintf("%s://%s%s", app.scheme, app.host, req.RequestURI)

	proxyReq, err := http.NewRequest(req.Method, url, bytes.NewReader(body))
	if err != nil {
		log.WithField("err", err).Error("new request", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	proxyReq.Header = make(http.Header)
	for h, val := range req.Header {
		proxyReq.Header[h] = val
	}

	resp, err := app.client.Do(proxyReq)
	if err != nil {
		log.WithField("err", err).Error("execute request", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	delete(req.Header, "Content-Length")

	for k, hvv := range req.Header {
		for _, hv := range hvv {
			w.Header().Add(k, hv)
		}
	}

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}
