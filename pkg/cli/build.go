package cli

import (
	"os"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"stackerbuild.io/stacker-bom/pkg/fs"
	stlog "stackerbuild.io/stacker-bom/pkg/log"
)

/*
build --name <doc> --pkgname <pkg> --pkgversion <version> --license <license> \
--dir dir1 --dir dir2 ... \
--file file1 --file file2 ... \
-o <output-file>.
*/
func BuildCmd() *cobra.Command {
	output := ""
	name := ""
	pkgname := ""
	pkgversion := ""
	paths := []string{}

	cmd := &cobra.Command{
		Use:   "build",
		Short: "Build a SBOM from project dir(s)/file(s) on the filesystem",
		Long:  "Build a SBOM from project dir(s)/file(s) on the filesystem",
		Run: func(cmd *cobra.Command, args []string) {
			if Verbose {
				stlog.SetLevel(stlog.DebugLevel)
			}

			if err := fs.BuildPackage(name, Author, Organization, License,
				pkgname, pkgversion, paths, output,
			); err != nil {
				log.Error().Err(err).Msg("build failed")
				os.Exit(1)
			}
		},
	}

	cmd.Flags().StringSliceVarP(&paths, "path", "p", []string{},
		"dir(s) to be included in this package (arg can be used multiple times)")
	cmd.Flags().StringVarP(&output, "output", "o", "", "output file")
	_ = cmd.MarkFlagRequired("output")
	cmd.Flags().StringVarP(&License, "license", "", "", "set license of this SBOM document")
	cmd.Flags().StringVarP(&pkgname, "pkgname", "", "", "set package name of this SBOM document")
	cmd.Flags().StringVarP(&name, "name", "", "", "set name of this SBOM document")
	cmd.Flags().StringVarP(&pkgversion, "pkgversion", "", "", "set package version of this SBOM document")

	return cmd
}
