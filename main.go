// Copyright 2022 The Swarm Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"log"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	optionNameInternalPort = "internal-port"
	optionNameExternalPort = "external-port"
	optionNameIngressURL   = "ingress-url"
)

func main() {
	cli := &cli{}

	cmd := &cobra.Command{
		Use:     "auth-proxy",
		PreRunE: cli.setupConfig,
		RunE:    cli.run,
	}

	cmd.Flags().Int(optionNameInternalPort, 1633, "Internal port for whitelisted resources.")
	cmd.Flags().Int(optionNameExternalPort, 1635, "External port for blacklisted resources.")
	cmd.Flags().String(optionNameIngressURL, "http://localhost:1633", "the URL of the ingress")

	if err := viper.BindPFlags(cmd.Flags()); err != nil {
		log.Fatal(err)
	}

	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

type cli struct {
	internalPort int
	externalPort int
	ingressURL   string
}

func (c *cli) setupConfig(cmd *cobra.Command, args []string) (err error) {
	c.internalPort = viper.GetInt(optionNameInternalPort)
	c.externalPort = viper.GetInt(optionNameExternalPort)
	c.ingressURL = viper.GetString(optionNameIngressURL)
	return
}

func (c *cli) run(cmd *cobra.Command, args []string) (err error) {
	ingress, err := url.Parse(c.ingressURL)
	if err != nil {
		return
	}

	app := proxy{
		internalPort: c.internalPort,
		externalPort: c.externalPort,
		scheme:       ingress.Scheme,
		host:         ingress.Host,
	}
	app.init()
	go app.run()

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	<-sigc
	app.shutdown()
	return
}
