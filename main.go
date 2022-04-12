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
	optionNamePort               = "port"
	optionNameTokenEncryptionKey = "token-encryption-key"
	optionNameAdminPasswordHash  = "admin-password"
	optionNameForwardURL         = "forward-url"
)

func main() {
	cli := &cli{}

	cmd := &cobra.Command{
		Use:     "auth-proxy",
		PreRunE: cli.setupConfig,
		RunE:    cli.run,
	}

	cmd.Flags().Int(optionNamePort, 1633, "Port to run on.")
	cmd.Flags().String(optionNameTokenEncryptionKey, "", "encryption key for token")
	cmd.Flags().String(optionNameAdminPasswordHash, "", "bcrypt hash of the admin password to get the security token")
	cmd.Flags().String(optionNameForwardURL, "http://localhost:1633", "the URL of the bee instance we want to proxy")

	if err := viper.BindPFlags(cmd.Flags()); err != nil {
		log.Fatal(err)
	}

	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

type cli struct {
	port                    int
	password, encryptionKey string
	forwardURL              string
}

func (c *cli) setupConfig(cmd *cobra.Command, args []string) (err error) {
	c.port = viper.GetInt(optionNamePort)
	c.encryptionKey = viper.GetString(optionNameTokenEncryptionKey)
	c.password = viper.GetString(optionNameAdminPasswordHash)
	c.forwardURL = viper.GetString(optionNameForwardURL)
	return
}

func (c *cli) run(cmd *cobra.Command, args []string) (err error) {
	auth, err := newAuthenticator(c.encryptionKey, c.password)
	if err != nil {
		return
	}

	rem, err := url.Parse(c.forwardURL)
	if err != nil {
		return
	}

	app := proxy{auth: auth, port: c.port, scheme: rem.Scheme, host: rem.Host}
	app.init()
	go app.run()

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	<-sigc
	app.shutdown()
	return
}
