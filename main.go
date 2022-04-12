package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func main() {
	cli := &cli{}

	cmd := &cobra.Command{
		Use:     "auth-proxy",
		PreRunE: cli.setupConfig,
		RunE:    cli.run,
	}

	cmd.Flags().Int("port", 1633, "Port to run on.")

	if err := viper.BindPFlags(cmd.Flags()); err != nil {
		log.Fatal(err)
	}

	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

type cli struct {
	port uint32
}

func (c *cli) setupConfig(cmd *cobra.Command, args []string) (err error) {
	c.port = viper.GetUint32("port")
	return
}

func (c *cli) run(cmd *cobra.Command, args []string) (err error) {
	log.Println("starting on port", c.port)
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	<-sigc
	return
}
