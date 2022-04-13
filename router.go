// Copyright 2022 The Swarm Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
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
	internalPort int
	externalPort int
	scheme, host string
	internal     *http.Server
	external     *http.Server
	client       *http.Client
}

func (app *proxy) init() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339})
	zerolog.SetGlobalLevel(zerolog.TraceLevel)

	external := mux.NewRouter()
	external.MatcherFunc(func(r *http.Request, _ *mux.RouteMatch) bool {
		// external - exclusive (ban list)
		match := forbidden.Match(r.URL.Path)
		log.Debug().Str("path", r.URL.Path).Bool("match", match).Msg("external")
		return !match
	}).HandlerFunc(app.forwardHandler)

	internal := mux.NewRouter()
	internal.MatcherFunc(func(r *http.Request, _ *mux.RouteMatch) bool {
		// internal - inclusive
		match := allowed.Match(r.URL.Path)
		log.Debug().Str("path", r.URL.Path).Bool("match", match).Msg("internal")
		return match
	}).HandlerFunc(app.forwardHandler)

	app.external = newServer(app.externalPort, external)
	app.internal = newServer(app.internalPort, internal)
	app.client = newClient()
}

func (app *proxy) run() {
	go func() {
		log.Info().Int("port", app.internalPort).Msg("starting internal")
		if err := app.internal.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatal().Err(err)
		}
	}()
	log.Info().Int("port", app.externalPort).Msg("starting external")
	if err := app.external.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatal().Err(err)
	}
}

func (app *proxy) shutdown() {
	log.Warn().Msg("shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := app.internal.Shutdown(ctx); err != nil && err != context.Canceled {
		panic(err)
	}
	if err := app.external.Shutdown(ctx); err != nil && err != context.Canceled {
		panic(err)
	}
	app.client.CloseIdleConnections()
	log.Warn().Msg("done.")
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

	proxyReq, err := http.NewRequestWithContext(req.Context(), req.Method, url, bytes.NewReader(body))
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
	if _, err = io.Copy(w, resp.Body); err != nil {
		log.Error().Err(err).Msg("write response body")
	}
}
