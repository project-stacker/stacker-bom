package apk

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/sha1" //nolint:gosec // used only to produce the sha1 checksum field
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/martencassel/go-apkutils/apk"
	"github.com/rs/zerolog/log"
	"sigs.k8s.io/bom/pkg/spdx"
	"stackerbuild.io/stacker-bom/pkg/bom"
	"stackerbuild.io/stacker-bom/pkg/buildgen"
)

// https://wiki.alpinelinux.org/wiki/Apk_spec

type IndexEntry struct {
	PullChecksum         string
	PackageName          string
	PackageVersion       string
	PackageArchitecture  string
	PackageSize          string
	PackageInstalledSize string
	PackageDescription   string
	PackageURL           string
	PackageLicense       string
	PackageOrigin        string
	PackageMaintainer    string
	BuildTimeStamp       string
	GitCommitAport       string
	PullDependencies     string
	PackageProvides      string
	Acls                 []*ACLEntry
}

type ACLEntry struct {
	DirName      string
	DirMode      string
	RelFileName  string
	FileMode     string
	FileChecksum string
}

// ParsePackage given a apk pkg emits a sbom.
func ParsePackage(input, output, author, organization, license string) error {
	fhandle, err := os.Open(input)
	if err != nil {
		log.Error().Err(err).Str("input", input).Msg("unable to open file")

		return err
	}
	defer fhandle.Close()

	apk, err := apk.ReadApk(fhandle)
	if err != nil {
		log.Error().Err(err).Str("path", input).Msg("unable to load package")

		return err
	}

	sdoc := spdx.NewDocument()
	sdoc.Creator.Person = author
	sdoc.Creator.Organization = organization
	sdoc.Creator.Tool = []string{"stackerbuild.io/sbom"}
	sdoc.Creator.Tool = []string{fmt.Sprintf("stackerbuild.io/sbom@%s", buildgen.Commit)}

	var pkglicense string

	if apk.PkgInfo.PkgLicense == "" {
		pkglicense = license
	} else {
		pkglicense = apk.PkgInfo.PkgLicense
	}

	spkg := &spdx.Package{
		Entity: spdx.Entity{
			Name: apk.PkgInfo.PkgName,
		},
		Version: apk.PkgInfo.PkgVer,
		Originator: struct {
			Person       string
			Organization string
		}{
			Person: apk.PkgInfo.PkgMaintainer,
		},
		FilesAnalyzed:   true,
		LicenseDeclared: pkglicense,
	}

	if err := sdoc.AddPackage(spkg); err != nil {
		log.Error().Err(err).Msg("unable to add package to doc")

		return err
	}

	tgzfh, err := os.Open(input)
	if err != nil {
		return err
	}
	defer tgzfh.Close()

	gzfh, err := gzip.NewReader(tgzfh)
	if err != nil {
		return err
	}

	trfh := tar.NewReader(gzfh)

	for {
		hdr, err := trfh.Next()
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

		if strings.HasPrefix(hdr.Name, ".PKGINFO") || strings.HasPrefix(hdr.Name, ".SIGN") {
			log.Warn().Str("name", hdr.Name).Msg("ignoring entry")

			continue
		}

		buf := make([]byte, hdr.Size)

		var bufsz int

		if bufsz, err = trfh.Read(buf); err != nil {
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
				Name: fmt.Sprintf("/%s", hdr.Name),
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
	}

	if err := bom.WriteDocument(sdoc, output); err != nil {
		log.Error().Err(err).Str("path", output).Msg("unable to write output")

		return err
	}

	return nil
}

func InstalledPackage(doc *spdx.Document, pkg *IndexEntry, files []string) error {
	spkg := &spdx.Package{
		Entity: spdx.Entity{
			Name: pkg.PackageName,
		},
		Version: pkg.PackageVersion,
		Originator: struct {
			Person       string
			Organization string
		}{
			Person: pkg.PackageMaintainer,
		},
		FilesAnalyzed:   true,
		LicenseDeclared: pkg.PackageLicense,
	}

	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}

			return err
		}

		if !info.Mode().IsRegular() {
			log.Warn().Str("file", file).Interface("mode", info.Mode()).Msg("skipping entry since not a regular file")

			continue
		}

		fhandle, err := os.Open(file)
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
		sfile.LicenseInfoInFile = pkg.PackageLicense
		sfile.SetEntity(
			&spdx.Entity{
				Name: file,
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

	if err := doc.AddPackage(spkg); err != nil {
		log.Error().Err(err).Msg("unable to add package to doc")

		return err
	}

	return nil
}

func InstalledPackages(doc *spdx.Document) error {
	path := "/lib/apk/db/installed"

	fhandle, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fhandle.Close()

	scanner := bufio.NewScanner(fhandle)
	scanner.Split(bufio.ScanLines)

	var pkg *IndexEntry
	lastDir := ""
	files := []string{}

	for scanner.Scan() {
		line := scanner.Text()

		match, err := regexp.MatchString(`^$`, line) //nolint:staticcheck
		if err != nil {
			return err
		}

		if match {
			if err := InstalledPackage(doc, pkg, files); err != nil {
				return err
			}

			// a new package
			pkg = &IndexEntry{}

			continue
		}

		if pkg == nil {
			// a new package
			pkg = &IndexEntry{}
		}

		rgxp := regexp.MustCompile(`^(?P<Key>[a-zA-Z-]+?):\s*(?P<Value>.*)$`)
		params := rgxp.FindStringSubmatch(line)
		key := params[rgxp.SubexpIndex("Key")]
		val := params[rgxp.SubexpIndex("Value")]

		switch key {
		case "C":
			log.Debug().Str("package", val).Msg("package found")

			if val[:2] != "Q1" {
				log.Error().Err(err).Str("type", val[:2]).Msg("unknown checksum type")
			}

			dec, err := base64.StdEncoding.DecodeString(val[2:])
			if err != nil {
				log.Error().Err(err).Str("type", val[:2]).Msg("unknown checksum type")

				return err
			}

			log.Info().Str("checksum", string(dec)).Msg("sha1")
		case "P":
			log.Debug().Str("package", val).Msg("package found")
			pkg.PackageName = val
		case "V":
			pkg.PackageVersion = val
		case "A":
			pkg.PackageArchitecture = val
		case "I":
			pkg.PackageDescription = val
		case "U":
			pkg.PackageURL = val
		case "L":
			pkg.PackageLicense = val
		case "o":
			pkg.PackageOrigin = val
		case "m":
			pkg.PackageMaintainer = val
		case "F":
			lastDir = val
		case "R":
			files = append(files, filepath.Join("/", lastDir, val))
		}
	}

	return nil
}
