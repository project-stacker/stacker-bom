package cli

import (
	"fmt"
	"os"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"stackerbuild.io/sbom/pkg/build"
	"stackerbuild.io/sbom/pkg/distro"
	"stackerbuild.io/sbom/pkg/fs"
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
		Short: "Generate a SBOM file from a package",
		Long:  "Generate a SBOM file from a package",
		Run: func(cmd *cobra.Command, args []string) {
			if err := distro.ParsePackage(input, output, Author, Organization, License); err != nil {
				log.Error().Err(err).Msg("generate failed")
				os.Exit(1)
			}
		},
	}

	cmd.Flags().StringVarP(&input, "input", "i", "", "input file")
	_ = cmd.MarkFlagRequired("input")
	cmd.Flags().StringVarP(&output, "output", "o", "", "output file")
	_ = cmd.MarkFlagRequired("output")
	cmd.Flags().StringVarP(&format, "format", "f", "spdx", "output format (spdx, default:spdx)")
	cmd.Flags().StringVarP(&Author, "author", "", "", "set author of this SBOM document")
	cmd.Flags().StringVarP(&Organization, "organization", "", "", "set organization of this SBOM document")
	cmd.Flags().StringVarP(&License, "license", "", "", "set license of this SBOM document")

	return cmd
}

func BuildCmd() *cobra.Command {
	input := ""
	output := ""
	pkgname := ""
	pkgversion := ""

	cmd := &cobra.Command{
		Use:   "build",
		Short: "Build a SBOM file from a filesystem layout",
		Long:  "Build a SBOM file from a filesystem layout",
		Run: func(cmd *cobra.Command, args []string) {
			if err := fs.ParsePackage(input, output, Author, Organization, License, pkgname, pkgversion); err != nil {
				log.Error().Err(err).Msg("generate failed")
				os.Exit(1)
			}
		},
	}

	cmd.Flags().StringVarP(&input, "input", "i", "", "input file")
	_ = cmd.MarkFlagRequired("input")
	cmd.Flags().StringVarP(&output, "output", "o", "", "output file")
	_ = cmd.MarkFlagRequired("output")
	cmd.Flags().StringVarP(&Author, "author", "", "", "set author of this SBOM document")
	cmd.Flags().StringVarP(&Organization, "organization", "", "", "set organization of this SBOM document")
	cmd.Flags().StringVarP(&License, "license", "", "", "set license of this SBOM document")
	cmd.Flags().StringVarP(&pkgname, "pkgname", "", "", "set package name of this SBOM document")
	cmd.Flags().StringVarP(&pkgversion, "pkgversion", "", "", "set package version of this SBOM document")

	return cmd
}

func VerifyCmd() *cobra.Command {
	input := ""

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a filesystem layout using a SBOM file",
		Long:  "Verify a filesystem layout using a SBOM file",
		Run: func(cmd *cobra.Command, args []string) {
			if err := fs.Verify(input); err != nil {
				log.Error().Err(err).Msg("verify failed")
				os.Exit(1)
			}
		},
	}

	cmd.Flags().StringVarP(&input, "input", "i", "", "input SBOM file")
	_ = cmd.MarkFlagRequired("input")

	return cmd
}

func NewCli() *cobra.Command {
	showVersion := false

	cmd := &cobra.Command{
		Use:   "sbom",
		Short: "sbom",
		Long:  "sbom",
		Run: func(cmd *cobra.Command, args []string) {
			if showVersion {
				version := ""
				if build.ReleaseTag != "" {
					version = build.ReleaseTag
					fmt.Printf("%s\n", version)
				} else {
					version = build.Commit
					fmt.Printf("%s\n", version)
				}
				fmt.Printf("%s", version)
				os.Exit(0)
			} else {
				_ = cmd.Usage()
			}
		},
	}

	cmd.AddCommand(BuildCmd())
	cmd.AddCommand(GenerateCmd())
	cmd.AddCommand(VerifyCmd())
	cmd.Flags().BoolVarP(&showVersion, "version", "v", false, "show the version and exit")
	cmd.Flags().BoolVarP(&Verbose, "verbose", "", false, "enable verbose logging")

	return cmd
}
