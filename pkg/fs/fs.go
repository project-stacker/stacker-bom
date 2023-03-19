package fs

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/minio/sha256-simd"
	"github.com/rs/zerolog/log"
	k8spdx "sigs.k8s.io/bom/pkg/spdx"
	"stackerbuild.io/sbom/pkg/build"
	"stackerbuild.io/sbom/pkg/errors"
)

func ParsePackage(input, output, author, organization, license, pkgname, pkgversion string) error {
	if _, err := os.Lstat(input); err != nil {
		log.Error().Err(err).Str("path", input).Msg("unable to find path")

		return err
	}

	kdoc := k8spdx.NewDocument()
	kdoc.Creator.Person = author
	kdoc.Creator.Organization = organization
	kdoc.Creator.Tool = []string{fmt.Sprintf("stackerbuild.io/sbom@%s", build.Commit)}

	pkg := &k8spdx.Package{
		Entity: k8spdx.Entity{
			Name: pkgname,
		},
		Version: pkgversion,
		Originator: struct {
			Person       string
			Organization string
		}{
			Person: author,
		},
		LicenseDeclared: license,
	}

	if err := kdoc.AddPackage(pkg); err != nil {
		log.Error().Err(err).Msg("unable to add package to doc")

		return err
	}

	err := filepath.Walk(input, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		fhandle, err := os.Open(path)
		if err != nil {
			return err
		}
		defer fhandle.Close()

		shaWriter := sha256.New()
		if _, err := io.Copy(shaWriter, fhandle); err != nil {
			return err
		}

		cksum := shaWriter.Sum(nil)

		file := k8spdx.NewFile()
		file.SetEntity(
			&k8spdx.Entity{
				Name:     path,
				Checksum: map[string]string{"SHA256": hex.EncodeToString(cksum)},
			},
		)
		if err := pkg.AddFile(file); err != nil {
			log.Error().Err(err).Msg("unable to add file to package")

			return err
		}

		return nil
	})
	if err != nil {
		log.Error().Err(err).Str("path", input).Msg("unable to walk dir")

		return err
	}

	if err := kdoc.Write(output); err != nil {
		log.Error().Err(err).Str("path", output).Msg("unable to write output")

		return err
	}

	return nil
}

func Verify(input string) error {
	kdoc, err := k8spdx.OpenDoc(input)
	if err != nil {
		log.Error().Err(err).Str("path", input).Msg("unable to open SBOM")

		return err
	}

	if kdoc == nil {
		log.Error().Str("path", input).Msg("invalid SBOM document")

		return fmt.Errorf("%s: %w", input, errors.ErrInvalidDoc)
	}

	for _, pkg := range kdoc.Packages {
		for _, file := range pkg.Files() {
			file.Entity.Opts = &k8spdx.ObjectOptions{}

			log.Info().Str("path", file.FileName).Msg("file entity")

			if err := file.ReadSourceFile(file.FileName); err != nil {
				log.Error().Err(err).Str("path", file.FileName).Msg("doesn't match entry in SBOM document")

				return err
			}
		}
	}

	return nil
}
