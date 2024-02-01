package fs

import (
	"crypto/sha1" //nolint:gosec // used only to produce the sha1 checksum field
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/formats/common/spdxhelpers"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/minio/sha256-simd"
	"github.com/rs/zerolog/log"
	"github.com/spdx/tools-golang/spdx"
	k8spdx "sigs.k8s.io/bom/pkg/spdx"
	stbom "stackerbuild.io/stacker-bom/pkg/bom"
	"stackerbuild.io/stacker-bom/pkg/buildgen"
)

func BuildPackageFromDir(input string, kdoc *k8spdx.Document, kpkg *k8spdx.Package, license string,
) error {
	if _, err := os.Lstat(input); err != nil {
		log.Error().Err(err).Str("path", input).Msg("unable to find path")

		return err
	}

	// use anchore/syft to catalog packages
	detection, err := source.Detect("dir:"+input, source.DefaultDetectConfig())
	if err != nil {
		log.Error().Err(err).Str("path", input).Msg("unable to parse path")

		return err
	}

	src, err := detection.NewSource(source.DefaultDetectionSourceConfig())
	if err != nil {
		log.Error().Err(err).Str("path", input).Msg("unable to parse path")

		return err
	}

	if err != nil {
		log.Error().Err(err).Str("path", input).Msg("unable to parse path")

		return err
	}

	scfg := cataloger.Config{
		Search: cataloger.SearchConfig{
			IncludeIndexedArchives:   true,
			IncludeUnindexedArchives: true,
			Scope:                    source.AllLayersScope,
		},
		Parallelism: 1,
	}

	pkgCatalog, relationships, actualDistro, err := syft.CatalogPackages(src, scfg)
	if err != nil {
		log.Error().Err(err).Str("path", input).Msg("unable to parse packages")

		return err
	}

	bom := sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages:          pkgCatalog,
			LinuxDistribution: actualDistro,
		},
		Relationships: relationships,
		Source:        src.Describe(),
	}
	sdoc := spdxhelpers.ToFormatModel(bom)
	sdoc.CreationInfo.Creators = []spdx.Creator{}

	tpkgs := map[string]*k8spdx.Package{}

	for _, tpkg := range sdoc.Packages {
		p := stbom.ConvertFromSyftPackage(tpkg)
		p.SetSPDXID(fmt.Sprintf("SPDXRef-%s", p.SPDXID()))
		p.LicenseConcluded = license
		p.LicenseDeclared = license
		tpkgs[p.SPDXID()] = p
	}

	kdoc.Packages = stbom.MergeMaps(kdoc.Packages, tpkgs)

	tfils := map[string]*k8spdx.File{}

	for _, tfil := range sdoc.Files {
		conv := stbom.ConvertFromSyftFile(tfil)
		tfils[conv.SPDXID()] = conv
	}

	kdoc.Files = stbom.MergeMaps(kdoc.Files, tfils)

	err = filepath.Walk(input, func(path string, info os.FileInfo, err error) error {
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

		kfile := k8spdx.NewFile()
		kfile.SetEntity(
			&k8spdx.Entity{
				Name: path,
				Checksum: map[string]string{
					"SHA1":   hex.EncodeToString(cksumSHA1[:]),
					"SHA256": hex.EncodeToString(cksumSHA256[:]),
				},
			},
		)
		kfile.LicenseInfoInFile = license
		if err := kpkg.AddFile(kfile); err != nil {
			log.Error().Err(err).Msg("unable to add file to package")

			return err
		}

		return nil
	})
	if err != nil {
		log.Error().Err(err).Str("path", input).Msg("unable to walk dir")

		return err
	}

	return nil
}

func BuildPackageFromFile(input string, kpkg *k8spdx.Package, license string) error {
	ifo, err := os.Lstat(input)
	if err != nil {
		log.Error().Err(err).Str("path", input).Msg("unable to find path")

		return err
	}

	// use anchore/syft to catalog packages
	detection, err := source.Detect("file:"+input, source.DefaultDetectConfig())
	if err != nil {
		log.Error().Err(err).Str("path", input).Msg("unable to parse path")

		return err
	}

	src, err := detection.NewSource(source.DefaultDetectionSourceConfig())
	if err != nil {
		log.Error().Err(err).Str("path", input).Msg("unable to parse path")

		return err
	}

	scfg := cataloger.Config{
		Search: cataloger.SearchConfig{
			IncludeIndexedArchives:   true,
			IncludeUnindexedArchives: true,
			Scope:                    source.AllLayersScope,
		},
		Parallelism: 1,
	}

	pkgCatalog, relationships, actualDistro, err := syft.CatalogPackages(src, scfg)
	if err != nil {
		log.Error().Err(err).Str("path", input).Msg("unable to parse packages")

		return err
	}

	bom := sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages:          pkgCatalog,
			LinuxDistribution: actualDistro,
		},
		Relationships: relationships,
		Source:        src.Describe(),
	}
	sdoc := spdxhelpers.ToFormatModel(bom)
	sdoc.CreationInfo.Creators = []spdx.Creator{}

	tpkgs := map[string]*k8spdx.Package{}

	for _, tpkg := range sdoc.Packages {
		conv := stbom.ConvertFromSyftPackage(tpkg)
		conv.LicenseDeclared = license
		tpkgs[conv.SPDXID()] = conv

		if err := kpkg.AddPackage(conv); err != nil {
			log.Error().Err(err).Str("path", conv.Name).Msg("unable to add package")

			return err
		}
	}

	tfils := map[string]*k8spdx.File{}

	for _, tfil := range sdoc.Files {
		conv := stbom.ConvertFromSyftFile(tfil)
		conv.LicenseConcluded = license
		tfils[conv.SPDXID()] = conv

		pfo, err := os.Lstat(conv.Name)
		if err != nil {
			log.Error().Err(err).Str("path", conv.Name).Msg("unable to find path")

			return err
		}

		if os.SameFile(ifo, pfo) {
			// we add this file below
			continue
		}

		if err := kpkg.AddFile(conv); err != nil {
			log.Error().Err(err).Str("path", conv.Name).Msg("unable to add file to package")

			return err
		}
	}

	fhandle, err := os.Open(input)
	if err != nil {
		return err
	}
	defer fhandle.Close()

	shaWriter := sha256.New()
	if _, err := io.Copy(shaWriter, fhandle); err != nil {
		return err
	}

	cksum := shaWriter.Sum(nil)

	kfile := k8spdx.NewFile()
	kfile.SetEntity(
		&k8spdx.Entity{
			Name:     input,
			Checksum: map[string]string{"SHA256": hex.EncodeToString(cksum)},
		},
	)

	if err := kpkg.AddFile(kfile); err != nil {
		log.Error().Err(err).Msg("unable to add file to package")

		return err
	}

	return nil
}

func BuildPackage(name, author, organization, license,
	pkgname, pkgversion string, inputPaths []string, output string,
) error {
	kdoc := k8spdx.NewDocument()
	kdoc.Name = name
	kdoc.Creator.Person = author
	kdoc.Creator.Organization = organization
	kdoc.Creator.Tool = []string{fmt.Sprintf("stackerbuild.io/sbom@%s", buildgen.Commit)}

	kpkg := &k8spdx.Package{
		Entity: k8spdx.Entity{
			Name:             pkgname,
			LicenseConcluded: license,
		},
		Version: pkgversion,
		Originator: struct {
			Person       string
			Organization string
		}{
			Person: author,
		},
		LicenseDeclared: license,
		FilesAnalyzed:   true,
	}

	if err := kdoc.AddPackage(kpkg); err != nil {
		log.Error().Err(err).Msg("unable to add package to doc")

		return err
	}

	for _, ipath := range inputPaths {
		pinfo, err := os.Lstat(ipath)
		if err != nil {
			log.Error().Err(err).Str("path", ipath).Msg("unable to stat path")

			return err
		}

		if pinfo.IsDir() {
			log.Info().Str("dir", ipath).Str("package", pkgname).Msg("adding dir to package")

			if err := BuildPackageFromDir(ipath, kdoc, kpkg, license); err != nil {
				return err
			}
		} else {
			log.Info().Str("file", ipath).Str("package", pkgname).Msg("adding file to package")

			if err := BuildPackageFromFile(ipath, kpkg, license); err != nil {
				return err
			}
		}
	}

	if err := stbom.WriteDocument(kdoc, output); err != nil {
		log.Error().Err(err).Str("path", output).Msg("unable to write output")

		return err
	}

	return nil
}
