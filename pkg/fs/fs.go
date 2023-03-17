package fs

import (
	"encoding/hex"
	"io"
	"os"
	"path/filepath"

	"github.com/minio/sha256-simd"
	"github.com/rs/zerolog/log"
	k8spdx "sigs.k8s.io/bom/pkg/spdx"
)

func ParsePackage(path, author, organization, license, pkgname, pkgversion string) error {
	if _, err := os.Lstat(path); err != nil {
		log.Error().Err(err).Str("path", path).Msg("unable to find path")

		return err
	}

	kdoc := k8spdx.NewDocument()
	kdoc.Creator.Person = author
	kdoc.Creator.Organization = organization
	kdoc.Creator.Tool = []string{"stackerbuild.io/sbom"}

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

	err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
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

		file := &k8spdx.File{
			Entity: k8spdx.Entity{
				Name:     path,
				Checksum: map[string]string{"SHA256": hex.EncodeToString(cksum)},
			},
		}
		if err := pkg.AddFile(file); err != nil {
			log.Error().Err(err).Msg("unable to add file to package")

			return err
		}

		return nil
	})
	if err != nil {
		log.Error().Err(err).Str("path", path).Msg("unable to walk dir")

		return err
	}

	spdxfile := path + ".k8s.spdx"
	if err := kdoc.Write(spdxfile); err != nil {
		log.Error().Err(err).Str("path", spdxfile).Msg("unable to write output")

		return err
	}

	return nil
}
