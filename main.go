// Copyright 2022 The Swarm Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"log"

	proxy "github.com/ethersphere/auth-proxy/internal"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func main() {
	cli := new(proxy.CLI)

	cmd := &cobra.Command{
		Short:   "proxies the calls to an ingress address separating internal and external http routes",
		Use:     "auth-proxy",
		PreRunE: cli.SetupConfig,
		RunE:    cli.Run,
	}

	cmd.Flags().Int(proxy.OptionNameInternalPort, 1643, "Internal port for whitelisted resources.")
	cmd.Flags().Int(proxy.OptionNameExternalPort, 1645, "External port for blacklisted resources.")
	cmd.Flags().String(proxy.OptionNameIngressURL, "http://localhost:1633", "the URL of the ingress")

	if err := viper.BindPFlags(cmd.Flags()); err != nil {
		log.Fatal(err)
	}

	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
