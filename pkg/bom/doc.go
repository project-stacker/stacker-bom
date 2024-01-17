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
	doc.Creator.Tool = []string{fmt.Sprintf("stackerbuild.io/sbom@%s", buildgen.Commit)}

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

// MergeDocuments in a given dir.
func MergeDocuments(dir, name, author, organization, output string) error {
	sdoc := spdx.NewDocument()
	sdoc.Name = name
	sdoc.Creator.Person = author
	sdoc.Creator.Organization = organization
	sdoc.Creator.Tool = []string{fmt.Sprintf("stackerbuild.io/stacker-bom@%s", buildgen.Commit)}

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

		sdoc.Files = MergeMaps(sdoc.Files, doc.Files)
		sdoc.Packages = MergeMaps(sdoc.Packages, doc.Packages)

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
