package main

import (
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/sirupsen/logrus"
	"stackerbuild.io/sbom/pkg/cli"
)

func main() {
	// setup logging
	logrus.SetLevel(logrus.ErrorLevel)

	zerolog.TimeFieldFormat = time.RFC3339
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	log.Logger = log.With().Caller().Logger().Output(zerolog.ConsoleWriter{Out: os.Stderr})

	if err := cli.NewCli().Execute(); err != nil {
		log.Error().Err(err).Msg("action failed")
		os.Exit(1)
	}
}
