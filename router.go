// Copyright 2022 The Swarm Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type proxy struct {
	internalPort   int
	externalPort   int
	scheme, host   string
	internalRouter *mux.Router
	externalRouter *mux.Router
	client         *http.Client
}

func (app *proxy) init() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339})
	zerolog.SetGlobalLevel(zerolog.TraceLevel)

	external := mux.NewRouter()
	external.MatcherFunc(func(r *http.Request, _ *mux.RouteMatch) bool {
		// external - exclusive (ban list)
		log.Info().Msg(r.URL.Path)
		match := forbid.Match(r.URL.Path)
		log.Debug().Str("path", r.URL.Path).Bool("match", match).Msg("external")
		return match
	}).HandlerFunc(app.forwardHandler)

	internal := mux.NewRouter()
	internal.MatcherFunc(func(r *http.Request, _ *mux.RouteMatch) bool {
		// internal - inclusive
		match := allow.Match(r.URL.Path)
		log.Debug().Str("path", r.URL.Path).Bool("match", match).Msg("internal")
		return match
	}).HandlerFunc(app.forwardHandler)

	app.externalRouter = external
	app.internalRouter = internal
	app.client = &http.Client{
		// TODO Transport: initTransport(),
	}
}

func (app *proxy) run() {
	go func() {
		log.Info().Int("port", app.internalPort).Msg("starting internal")
		log.Fatal().Err(http.ListenAndServe(fmt.Sprintf(":%d", app.internalPort), app.internalRouter))
	}()
	log.Info().Int("port", app.externalPort).Msg("starting external")
	err := http.ListenAndServe(fmt.Sprintf(":%d", app.externalPort), app.externalRouter)
	log.Fatal().Err(err)
}

func (app *proxy) shutdown() {
	log.Warn().Msg("shutting down")
	app.client.CloseIdleConnections()
}

func (app *proxy) forwardHandler(w http.ResponseWriter, req *http.Request) {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		log.Error().Err(err).Msg("read request body")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	req.Body = ioutil.NopCloser(bytes.NewReader(body))

	url := fmt.Sprintf("%s://%s%s", app.scheme, app.host, req.RequestURI)

	proxyReq, err := http.NewRequest(req.Method, url, bytes.NewReader(body))
	if err != nil {
		log.Error().Err(err).Msg("new request")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	proxyReq.Header = make(http.Header)
	for h, val := range req.Header {
		proxyReq.Header[h] = val
	}

	resp, err := app.client.Do(proxyReq)
	if err != nil {
		log.Error().Err(err).Msg("execute request")
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
