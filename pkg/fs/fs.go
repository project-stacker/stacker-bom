package fs

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/formats"
	"github.com/anchore/syft/syft/formats/common/spdxhelpers"
	"github.com/anchore/syft/syft/formats/spdxjson"
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

func BuildPackageFromDir(input, pkgname string, kdoc *k8spdx.Document, kpkg *k8spdx.Package,
) error {
	if _, err := os.Lstat(input); err != nil {
		log.Error().Err(err).Str("path", input).Msg("unable to find path")

		return err
	}

	// use anchore/syft to catalog packages
	src, err := source.NewFromDirectoryWithName(input, pkgname)
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

	pkgCatalog, relationships, actualDistro, err := syft.CatalogPackages(&src, scfg)
	if err != nil {
		log.Error().Err(err).Str("path", input).Msg("unable to parse packages")

		return err
	}

	bom := sbom.SBOM{
		Artifacts: sbom.Artifacts{
			PackageCatalog:    pkgCatalog,
			LinuxDistribution: actualDistro,
		},
		Relationships: relationships,
		Source:        src.Metadata,
	}
	sdoc := spdxhelpers.ToFormatModel(bom)
	sdoc.CreationInfo.Creators = []spdx.Creator{}

	contents, err := formats.Encode(bom, spdxjson.Format())
	if err != nil {
		return err
	}

	file, err := os.CreateTemp("", "stacker-bom-syft-")
	if err != nil {
		return err
	}

	defer os.Remove(file.Name())

	if err := os.WriteFile(file.Name(), contents, 0o644); err != nil { //nolint:gosec,gomnd
		return err
	}

	tdoc, err := k8spdx.OpenDoc(file.Name())
	if err != nil {
		return err
	}

	kdoc.Files = stbom.MergeMaps(kdoc.Files, tdoc.Files)
	kdoc.Packages = stbom.MergeMaps(kdoc.Packages, tdoc.Packages)

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

		shaWriter := sha256.New()
		if _, err := io.Copy(shaWriter, fhandle); err != nil {
			return err
		}

		cksum := shaWriter.Sum(nil)

		kfile := k8spdx.NewFile()
		kfile.SetEntity(
			&k8spdx.Entity{
				Name:     path,
				Checksum: map[string]string{"SHA256": hex.EncodeToString(cksum)},
			},
		)
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

func BuildPackageFromFile(input string, kpkg *k8spdx.Package) error {
	if _, err := os.Lstat(input); err != nil {
		log.Error().Err(err).Str("path", input).Msg("unable to find path")

		return err
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

			if err := BuildPackageFromDir(ipath, pkgname, kdoc, kpkg); err != nil {
				return err
			}
		} else {
			log.Info().Str("file", ipath).Str("package", pkgname).Msg("adding dir to package")

			if err := BuildPackageFromFile(ipath, kpkg); err != nil {
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
