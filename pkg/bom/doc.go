package bom

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"
	"sigs.k8s.io/bom/pkg/serialize"
	"sigs.k8s.io/bom/pkg/spdx"
	"stackerbuild.io/stacker-bom/pkg/buildgen"
)

func NewDocument(author, organization string) *spdx.Document {
	doc := spdx.NewDocument()
	doc.Creator.Person = author
	doc.Creator.Organization = organization
	doc.Creator.Tool = []string{"stackerbuild.io/sbom@" + buildgen.Commit}

	return doc
}

func WriteDocument(doc *spdx.Document, path string) error {
	renderer := &serialize.JSON{}

	markup, err := renderer.Serialize(doc)
	if err != nil {
		return fmt.Errorf("serializing document: %w", err)
	}

	if err := os.WriteFile(path, []byte(markup), 0o644); err != nil { //nolint:gosec,gomnd // G306: Expect WriteFile
		return fmt.Errorf("writing SBOM: %w", err)
	}

	if _, err := spdx.OpenDoc(path); err != nil {
		return fmt.Errorf("merging SBOM: %w", err)
	}

	return nil
}

func MergeMaps[K comparable, V any](map1 map[K]V, map2 map[K]V) map[K]V {
	merged := make(map[K]V)
	for key, value := range map1 {
		merged[key] = value
	}

	for key, value := range map2 {
		merged[key] = value
	}

	return merged
}

// merge pkgs from doc2 to doc1.
func mergePackages(doc1, doc2 *spdx.Document) {
	for _, pkg2 := range doc2.Packages {
		found := false

		var pkg1 *spdx.Package

		for _, pkg1 = range doc1.Packages {
			if pkg1.Name == pkg2.Name && pkg1.Version == pkg2.Version {
				found = true

				break
			}
		}

		if !found {
			_ = doc1.AddPackage(pkg2)

			log.Info().Str("package", pkg2.Name).Str("version", pkg2.Version).Msg("merging package")

			continue
		}

		var file2 *spdx.File

		for _, file2 = range pkg2.Files() {
			found = false

			for _, file1 := range pkg1.Files() {
				if file1.Name == file2.Name {
					found = true

					break
				}
			}

			if !found {
				_ = pkg1.AddFile(file2)

				log.Info().Str("package", pkg1.Name).Str("version", pkg1.Version).
					Str("file", file2.Name).Msg("merging file to package")
			}
		}
	}
}

// merge files from doc2 to doc1.
func mergeFiles(doc1, doc2 *spdx.Document) {
	for _, file2 := range doc2.Files {
		found := false

		var file1 *spdx.File

		for _, file1 = range doc1.Files {
			if file1.Name == file2.Name {
				found = true

				break
			}
		}

		if !found {
			_ = doc1.AddFile(file2)

			log.Info().Str("file", file2.Name).Msg("merging file to document")
		}
	}
}

// MergeDocuments in a given dir.
func MergeDocuments(dir, namespace, name, author, organization, output string) error {
	sdoc := spdx.NewDocument()
	sdoc.Namespace = namespace
	sdoc.Name = name
	sdoc.Creator.Person = author
	sdoc.Creator.Organization = organization
	sdoc.Creator.Tool = []string{"stackerbuild.io/stacker-bom@" + buildgen.Commit}

	mcount := 0

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		doc, err := spdx.OpenDoc(path)
		if err != nil {
			log.Warn().Str("path", path).Interface("error", err).Msg("unable to parse file")

			return nil
		}

		mergePackages(sdoc, doc)
		mergeFiles(sdoc, doc)

		log.Info().Str("path", path).Msg("file found for merging")

		mcount++

		return nil
	})
	if err != nil {
		log.Error().Err(err).Str("path", dir).Msg("unable to walk dir")

		return err
	}

	if mcount > 0 {
		if err := WriteDocument(sdoc, output); err != nil {
			log.Error().Err(err).Str("name", output).Msg("unable to write merged doc")

			return err
		}

		log.Info().Int("files", mcount).Str("dir", dir).Str("output", output).Msg("merged files")
	}

	return nil
}
