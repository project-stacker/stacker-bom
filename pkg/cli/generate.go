package cli

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"stackerbuild.io/stacker-bom/pkg/distro"
)

// generate --input <pkg> -o <sbom-file>.
func GenerateCmd() *cobra.Command {
	input := ""
	output := ""

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate a SBOM directly from a distro package",
		Long:  "Generate a SBOM directly from a distro package",
		Run: func(cmd *cobra.Command, args []string) {
			if Verbose {
				zerolog.SetGlobalLevel(zerolog.DebugLevel)
			}

			if err := distro.ParsePackage(input, Author, Organization, License, output); err != nil {
				log.Error().Err(err).Msg("generate failed")
				os.Exit(1)
			}
		},
	}

	cmd.Flags().StringVarP(&input, "input", "i", "", "input file")
	_ = cmd.MarkFlagRequired("input")
	cmd.Flags().StringVarP(&output, "output", "o", "", "output file")
	_ = cmd.MarkFlagRequired("output")

	return cmd
}
