// Copyright 2022 The Swarm Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package proxy

import (
	"net/url"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type CLI struct {
	InternalPort int
	ExternalPort int
	IngressURL   string
}

const (
	OptionNameInternalPort = "internal-port"
	OptionNameExternalPort = "external-port"
	OptionNameIngressURL   = "ingress-url"
)

func (c *CLI) SetupConfig(cmd *cobra.Command, args []string) error {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.SetConfigType("yml")
	viper.AddConfigPath(".")
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return err
		}
	}
	c.InternalPort = viper.GetInt(OptionNameInternalPort)
	c.ExternalPort = viper.GetInt(OptionNameExternalPort)
	c.IngressURL = viper.GetString(OptionNameIngressURL)
	return nil
}

func (c *CLI) Run(cmd *cobra.Command, args []string) (err error) {
	ingress, err := url.Parse(c.IngressURL)
	if err != nil {
		return
	}
	app := proxy{
		internalPort: c.InternalPort,
		externalPort: c.ExternalPort,
		scheme:       ingress.Scheme,
		host:         ingress.Host,
	}
	app.init()
	go app.run()

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	<-done

	app.shutdown()
	return
}
