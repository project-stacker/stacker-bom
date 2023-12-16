package deb

import (
	"archive/tar"
	"bufio"
	"crypto/sha1" //nolint:gosec // used only to produce the sha1 checksum field
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/minio/sha256-simd"
	"github.com/mitchellh/mapstructure"
	"github.com/rs/zerolog/log"
	"pault.ag/go/debian/deb"
	"sigs.k8s.io/bom/pkg/spdx"
	"stackerbuild.io/stacker-bom/pkg/bom"
	"stackerbuild.io/stacker-bom/pkg/buildgen"
)

// ParsePackage given a deb pkg emits a sbom.
func ParsePackage(input, output, author, organization, license string) error {
	debfile, _, err := deb.LoadFile(input)
	if err != nil {
		log.Error().Err(err).Str("path", input).Msg("unable to load package")

		return err
	}

	defer debfile.Close()

	sdoc := spdx.NewDocument()
	sdoc.Creator.Person = author
	sdoc.Creator.Organization = organization
	sdoc.Creator.Tool = []string{"stackerbuild.io/sbom"}
	sdoc.Creator.Tool = []string{fmt.Sprintf("stackerbuild.io/sbom@%s", buildgen.Commit)}

	spkg := &spdx.Package{
		Entity: spdx.Entity{
			Name: debfile.Control.Package,
		},
		Version: debfile.Control.Version.String(),
		Originator: struct {
			Person       string
			Organization string
		}{
			Person: debfile.Control.Maintainer,
		},
		FilesAnalyzed:   true,
		LicenseDeclared: license,
	}

	if err := sdoc.AddPackage(spkg); err != nil {
		log.Error().Err(err).Msg("unable to add package to doc")

		return err
	}

	for {
		hdr, err := debfile.Data.Next()
		if err != nil && !errors.Is(err, io.EOF) {
			log.Error().Err(err).Msg("unable to get next content")

			return err
		}

		if hdr == nil {
			break
		}

		if hdr.Typeflag != tar.TypeReg {
			log.Warn().Str("name", hdr.Name).Msg("ignoring entry")

			continue
		}

		buf := make([]byte, hdr.Size)

		var bufsz int

		if bufsz, err = debfile.Data.Read(buf); err != nil {
			if !errors.Is(err, io.EOF) {
				log.Error().Err(err).Str("name", hdr.Name).Msg("unable to read content")

				return err
			}
		}

		cksumSHA1 := sha1.Sum(buf) //nolint:gosec // used only to produce the sha1 checksum field
		cksumSHA256 := sha256.Sum256(buf)

		log.Info().Str("name", hdr.Name).
			Int("size", bufsz).
			Str("cksum", fmt.Sprintf("SHA256:%s", hex.EncodeToString(cksumSHA256[:]))).
			Msg("file entry detected")

		sfile := &spdx.File{
			Entity: spdx.Entity{
				Name: hdr.Name[1:],
				Checksum: map[string]string{
					"SHA1":   hex.EncodeToString(cksumSHA1[:]),
					"SHA256": hex.EncodeToString(cksumSHA256[:]),
				},
			},
			LicenseInfoInFile: license,
		}
		if err := spkg.AddFile(sfile); err != nil {
			log.Error().Err(err).Msg("unable to add file to package")

			return err
		}

		if strings.HasPrefix(hdr.Name, "./usr/share/doc/") && strings.HasSuffix(hdr.Name, "copyright") {
			log.Info().Str("path", hdr.Name).Msg("license/copyright found")
			spkg.CopyrightText = string(buf)
		}
	}

	if err := bom.WriteDocument(sdoc, output); err != nil {
		log.Error().Err(err).Str("path", output).Msg("unable to write output")

		return err
	}

	return nil
}

type Package struct {
	Package            string
	Status             string
	Priority           string
	Architecture       string
	MultiArch          string `yaml:"Multi-Arch"`
	Maintainer         string
	Version            string
	Section            string
	InstalledSize      string `yaml:"Installed-Size"`
	Depends            string
	Recommends         string
	Suggests           string
	Breaks             string
	PreDepends         string `yaml:"Pre-Depends"`
	Description        string
	Source             string
	Homepage           string
	Essential          string
	ConfigVersion      string `yaml:"Config-Version"`
	OriginalMaintainer string `yaml:"Original-Maintainer"`
	Enhances           string
	Replaces           string
	Conffiles          string
}

func InstalledPackages(doc *spdx.Document) error {
	pkgs := []Package{}

	path := "/var/lib/dpkg/status"

	fhandle, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fhandle.Close()

	scanner := bufio.NewScanner(fhandle)
	scanner.Split(bufio.ScanLines)
	lastkey := ""
	lastline := ""
	pkgMap := map[string]string{}

	for scanner.Scan() {
		line := scanner.Text()

		match, err := regexp.MatchString(`^$`, line) //nolint:staticcheck
		if err != nil {
			return err
		}

		if match {
			var pkg Package
			msc := &mapstructure.DecoderConfig{Result: &pkg}

			msdec, err := mapstructure.NewDecoder(msc)
			if err != nil {
				return err
			}

			if err := msdec.Decode(pkgMap); err != nil {
				return err
			}

			pkgs = append(pkgs, pkg)

			// a new package
			pkgMap = map[string]string{}
		} else {
			match, err = regexp.MatchString(`^\s+.*$`, line) //nolint:staticcheck
			if err != nil {
				return err
			}

			if match {
				// multiline string
				lastline += line
			} else {
				pkgMap[lastkey] = lastline
				lastline = ""

				rgxp := regexp.MustCompile(`^(?P<Key>[a-zA-Z-]+?):\s*(?P<Value>.*)$`)
				params := rgxp.FindStringSubmatch(line)
				key := params[rgxp.SubexpIndex("Key")]
				if rgxp.SubexpIndex("Value") < 0 {
					lastkey = key
				} else {
					pkgMap[params[rgxp.SubexpIndex("Key")]] = params[rgxp.SubexpIndex("Value")]
				}
			}
		}
	}

	for _, pkg := range pkgs {
		// filter removed packages
		parts := strings.Split(pkg.Status, " ")
		good := 0

		for _, part := range parts {
			if part == "install" || part == "ok" || part == "installed" {
				good++

				continue
			}
		}

		if good != 3 { //nolint:gomnd
			log.Warn().Str("package", pkg.Package).Msg("pruned or not properly installed?")

			continue
		}

		_, err := os.Lstat(fmt.Sprintf("/var/lib/dpkg/info/%s.list", pkg.Package))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				_, err := os.Lstat(fmt.Sprintf("/var/lib/dpkg/info/%s:%s.list", pkg.Package, pkg.Architecture))
				if err != nil {
					log.Error().Err(err).Msg("distro pkg mgmt state is missing!")

					return err
				}

				err = InstalledPackage(doc, pkg, fmt.Sprintf("/var/lib/dpkg/info/%s:%s.list", pkg.Package, pkg.Architecture))
				if err != nil {
					log.Error().Err(err).Msg("bom could be incomplete")

					continue
				}
			}
		} else {
			err = InstalledPackage(doc, pkg, fmt.Sprintf("/var/lib/dpkg/info/%s.list", pkg.Package))
			if err != nil {
				log.Error().Err(err).Msg("bom could be incomplete")

				continue
			}
		}

		log.Info().Str("package", pkg.Package).Str("version", pkg.Version).Msg("discovered installed package")
	}

	return nil
}

func InstalledPackage(doc *spdx.Document, pkg Package, path string) error {
	spkg := &spdx.Package{
		Entity: spdx.Entity{
			Name: pkg.Package,
		},
		Version: pkg.Version,
		Originator: struct {
			Person       string
			Organization string
		}{
			Person: pkg.Maintainer,
		},
		FilesAnalyzed:   true,
		LicenseDeclared: "unknown",
	}

	fhandle, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fhandle.Close()

	scanner := bufio.NewScanner(fhandle)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		line := scanner.Text()

		info, err := os.Lstat(line)
		if err != nil {
			log.Warn().Str("package", pkg.Package).Str("version", pkg.Version).Str("file", line).Msg("file is missing!")

			continue
		}

		if !info.Mode().IsRegular() {
			continue
		}

		fhandle, err := os.Open(line)
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
				Name: line,
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

		if strings.HasPrefix(line, "/usr/share/doc/") && strings.HasSuffix(strings.ToLower(line), "copyright") {
			log.Info().Str("path", line).Msg("license/copyright found")

			buf, err := os.ReadFile(line)
			if err != nil {
				log.Error().Err(err).Str("path", line).Msg("unable to read copyright")

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
