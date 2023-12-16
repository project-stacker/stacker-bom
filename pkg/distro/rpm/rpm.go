package rpm

import (
	"crypto/sha1" //nolint:gosec // used only to produce the sha1 checksum field
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	rpmdb "github.com/knqyf263/go-rpmdb/pkg"
	"github.com/rs/zerolog/log"
	"github.com/sassoftware/go-rpmutils"
	"sigs.k8s.io/bom/pkg/spdx"
	"stackerbuild.io/stacker-bom/pkg/bom"
	"stackerbuild.io/stacker-bom/pkg/buildgen"
)

// ParsePackage given a rpm pkg emits a sbom.
func ParsePackage(input, output, author, organization, license string) error {
	fhandle, err := os.Open(input)
	if err != nil {
		log.Error().Err(err).Str("path", input).Msg("unable to open file")

		return err
	}

	defer fhandle.Close()

	rpmfile, err := rpmutils.ReadRpm(fhandle)
	if err != nil {
		log.Error().Err(err).Str("path", input).Msg("unable to load package")

		return err
	}

	// Getting metadata
	nevra, err := rpmfile.Header.GetNEVRA()
	if err != nil {
		return err
	}

	vendor, err := rpmfile.Header.GetStrings(rpmutils.VENDOR)
	if err != nil {
		return err
	}

	lic, err := rpmfile.Header.GetStrings(rpmutils.LICENSE)
	if err != nil {
		return err
	}

	var pkglicense string

	if len(lic) == 0 {
		pkglicense = license
	} else {
		pkglicense = strings.Join(lic, " ")
	}

	desc, err := rpmfile.Header.GetStrings(rpmutils.DESCRIPTION)
	if err != nil {
		return err
	}

	url, err := rpmfile.Header.GetStrings(rpmutils.URL)
	if err != nil {
		return err
	}

	sdoc := spdx.NewDocument()
	sdoc.Creator.Person = author
	sdoc.Creator.Organization = organization
	sdoc.Creator.Tool = []string{"stackerbuild.io/sbom"}
	sdoc.Creator.Tool = []string{fmt.Sprintf("stackerbuild.io/sbom@%s", buildgen.Commit)}

	spkg := &spdx.Package{
		Entity: spdx.Entity{
			Name:             nevra.Name,
			DownloadLocation: url[0],
		},
		Version: nevra.Version,
		Comment: desc[0],
		Originator: struct {
			Person       string
			Organization string
		}{
			Organization: vendor[0],
		},
		FilesAnalyzed:   true,
		LicenseDeclared: pkglicense,
	}

	if err := sdoc.AddPackage(spkg); err != nil {
		log.Error().Err(err).Msg("unable to add package to doc")

		return err
	}

	finfos, err := rpmfile.Header.GetFiles()
	if err != nil {
		return err
	}

	for _, finfo := range finfos {
		info, err := os.Lstat(finfo.Name())
		if err != nil {
			log.Warn().Str("package", nevra.Name).Str("version", nevra.Version).Str("file", finfo.Name()).Msg("file is missing!")

			continue
		}

		if !info.Mode().IsRegular() {
			continue
		}

		fhandle, err := os.Open(finfo.Name())
		if err != nil {
			return err
		}
		defer fhandle.Close()

		buf := make([]byte, info.Size())

		var bufsz int

		if bufsz, err = fhandle.Read(buf); err != nil {
			if !errors.Is(err, io.EOF) {
				log.Error().Err(err).Str("name", finfo.Name()).Msg("unable to read content")

				return err
			}
		}

		cksumSHA1 := sha1.Sum(buf) //nolint:gosec // used only to produce the sha1 checksum field
		cksumSHA256 := sha256.Sum256(buf)

		log.Info().Str("name", info.Name()).
			Int("size", bufsz).
			Str("cksum", fmt.Sprintf("SHA256:%s", hex.EncodeToString(cksumSHA256[:]))).
			Msg("file entry detected")

		sfile := spdx.NewFile()
		sfile.LicenseInfoInFile = pkglicense
		sfile.SetEntity(
			&spdx.Entity{
				Name: finfo.Name(),
				Checksum: map[string]string{
					"SHA1":   hex.EncodeToString(cksumSHA1[:]),
					"SHA256": hex.EncodeToString(cksumSHA256[:]),
				},
			},
		)

		if err := spkg.AddFile(sfile); err != nil {
			log.Error().Err(err).Msg("unable to add file to package")

			return err
		}
	}

	if err := bom.WriteDocument(sdoc, output); err != nil {
		log.Error().Err(err).Str("path", output).Msg("unable to write output")

		return err
	}

	return nil
}

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
		FilesAnalyzed:   true,
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

		buf := make([]byte, info.Size())

		var bufsz int

		if bufsz, err = fhandle.Read(buf); err != nil {
			if !errors.Is(err, io.EOF) {
				log.Error().Err(err).Str("name", info.Name()).Msg("unable to read content")

				return err
			}
		}

		cksumSHA1 := sha1.Sum(buf) //nolint:gosec // used only to produce the sha1 checksum field
		cksumSHA256 := sha256.Sum256(buf)

		log.Info().Str("name", info.Name()).
			Int("size", bufsz).
			Str("cksum", fmt.Sprintf("SHA256:%s", hex.EncodeToString(cksumSHA256[:]))).
			Msg("file entry detected")

		sfile := spdx.NewFile()
		sfile.LicenseInfoInFile = "unknown"
		sfile.SetEntity(
			&spdx.Entity{
				Name: ifile.Path,
				Checksum: map[string]string{
					"SHA1":   hex.EncodeToString(cksumSHA1[:]),
					"SHA256": hex.EncodeToString(cksumSHA256[:]),
				},
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
	pkgdb, err := rpmdb.Open("/var/lib/rpm/Packages")
	if err != nil {
		pkgdb, err = rpmdb.Open("/var/lib/rpm/rpmdb.sqlite")
		if err != nil {
			log.Error().Err(err).Msg("unable to open package db")

			return err
		}
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
