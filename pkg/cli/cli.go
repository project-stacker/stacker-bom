package cli

import (
	"os"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"stackerbuild.io/sbom/pkg/distro"
)

//nolint:gochecknoglobals
var (
	Author       string
	Organization string
	License      string
	Verbose      bool
)

func GenerateCmd() *cobra.Command {
	input := ""
	output := ""
	format := ""

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "generate",
		Long:  "generate",
		Run: func(cmd *cobra.Command, args []string) {
			if err := distro.ParsePackage(input, Author, Organization, License); err != nil {
				log.Error().Err(err).Msg("generate failed")
				os.Exit(1)
			}
		},
	}

	cmd.Flags().StringVarP(&input, "input", "i", "", "input file")
	_ = cmd.MarkFlagRequired("input")
	cmd.Flags().StringVarP(&output, "output", "o", "", "output file")
	cmd.Flags().StringVarP(&format, "format", "f", "spdx", "output format (spdx, default:spdx)")
	cmd.Flags().StringVarP(&Author, "author", "", "", "set author of this SBOM document")
	cmd.Flags().StringVarP(&Organization, "organization", "", "", "set organization of this SBOM document")
	cmd.Flags().StringVarP(&License, "license", "", "", "set license of this SBOM document")

	return cmd
}

func BuildCmd() *cobra.Command {
	input := ""
	cmd := &cobra.Command{
		Use:   "build",
		Short: "build",
		Long:  "build",
		Run: func(cmd *cobra.Command, args []string) {
		},
	}

	cmd.Flags().StringVarP(&input, "input", "i", "", "input file")
	_ = cmd.MarkFlagRequired("input")
	cmd.Flags().StringVarP(&Author, "author", "", "", "set author of this SBOM document")
	cmd.Flags().StringVarP(&Organization, "organization", "", "", "set organization of this SBOM document")
	cmd.Flags().StringVarP(&License, "license", "", "", "set license of this SBOM document")

	return cmd
}

func NewCli() *cobra.Command {
	showVersion := false

	cmd := &cobra.Command{
		Use:   "sbom",
		Short: "sbom",
		Long:  `A SBOM generator tool`,
		Run: func(cmd *cobra.Command, args []string) {
			if showVersion {
				os.Exit(0)
			} else {
				_ = cmd.Usage()
			}
		},
	}

	cmd.AddCommand(BuildCmd())
	cmd.AddCommand(GenerateCmd())
	cmd.Flags().BoolVarP(&showVersion, "version", "v", false, "show the version and exit")
	cmd.Flags().BoolVarP(&Verbose, "verbose", "", false, "enable verbose logging")

	return cmd
}
