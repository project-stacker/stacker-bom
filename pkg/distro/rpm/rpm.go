package rpm

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strings"

	rpmdb "github.com/knqyf263/go-rpmdb/pkg"
	"github.com/rs/zerolog/log"
	"sigs.k8s.io/bom/pkg/spdx"
)

func InstalledPackage(doc *spdx.Document, pkg *rpmdb.PackageInfo) error {
	spkg := &spdx.Package{
		Entity: spdx.Entity{
			Name: pkg.Name,
		},
		Version: pkg.Version,
		Originator: struct {
			Person       string
			Organization string
		}{
			Person: pkg.Vendor,
		},
		LicenseDeclared: pkg.License,
	}

	ifiles, err := pkg.InstalledFiles()
	if err != nil {
		log.Error().Err(err).Str("package", pkg.Name).Str("version", pkg.Version).Msg("unable to get installed files")

		return err
	}

	for _, ifile := range ifiles {
		info, err := os.Lstat(ifile.Path)
		if err != nil {
			log.Warn().Str("package", pkg.Name).Str("version", pkg.Version).Str("file", ifile.Path).Msg("file is missing!")

			continue
		}

		if !info.Mode().IsRegular() {
			continue
		}

		fhandle, err := os.Open(ifile.Path)
		if err != nil {
			return err
		}
		defer fhandle.Close()

		shaWriter := sha256.New()
		if _, err := io.Copy(shaWriter, fhandle); err != nil {
			return err
		}

		cksum := shaWriter.Sum(nil)

		sfile := spdx.NewFile()
		sfile.SetEntity(
			&spdx.Entity{
				Name:     ifile.Path,
				Checksum: map[string]string{"SHA256": hex.EncodeToString(cksum)},
			},
		)

		if err := spkg.AddFile(sfile); err != nil {
			log.Error().Err(err).Msg("unable to add file to package")

			return err
		}

		if strings.HasPrefix(ifile.Path, "/usr/share/doc/") && strings.HasSuffix(strings.ToLower(ifile.Path), "copyright") {
			log.Info().Str("path", ifile.Path).Msg("license/copyright found")

			buf, err := os.ReadFile(ifile.Path)
			if err != nil {
				log.Error().Err(err).Str("path", ifile.Path).Msg("unable to read copyright")

				return err
			}

			spkg.CopyrightText = string(buf)
		}
	}

	if err := doc.AddPackage(spkg); err != nil {
		log.Error().Err(err).Msg("unable to add package to doc")

		return err
	}

	return nil
}

func InstalledPackages(doc *spdx.Document) error {
	pkgdb, err := rpmdb.Open("/var/lib/rpm/rpmdb.sqlite")
	if err != nil {
		log.Error().Err(err).Msg("unable to open package db")

		return err
	}

	pkgList, err := pkgdb.ListPackages()
	if err != nil {
		return err
	}

	for _, pkg := range pkgList {
		if err := InstalledPackage(doc, pkg); err != nil {
			log.Error().Err(err).Msg("bom could be incomplete")

			continue
		}

		log.Info().Str("package", pkg.Name).Str("version", pkg.Version).Msg("discovered installed package")
	}

	return nil
}
