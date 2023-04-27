package fs

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/minio/sha256-simd"
	"github.com/rs/zerolog/log"
	"stackerbuild.io/stacker-bom/errors"
)

type Entry struct {
	Path     string `yaml:"path" json:"path"`
	Size     int64  `yaml:"size" json:"size"`
	Checksum string `yaml:"checksum" json:"checksum"`
	Mode     string `yaml:"mode" json:"mode"`
}

type Inventory struct {
	Entries []Entry `yaml:"entries" json:"entries"`
}

func isExcluded(path string, exclude []string) bool {
	for _, e := range exclude {
		if path == e {
			return true
		}
	}

	return false
}

func GenerateInventory(root string, exclude []string, output string) error {
	entries := []Entry{}

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		log.Debug().Str("path", path).Err(err).Msg("file/dir found")

		if err != nil {
			return nil //nolint:nilerr
		}

		if info.IsDir() && isExcluded(path, exclude) {
			// exclude/skip these dirs
			return filepath.SkipDir
		}

		// skip excluded files
		if isExcluded(path, exclude) {
			return nil
		}

		// skip dirs for generating the inventory
		if info.IsDir() {
			return nil
		}

		entry := Entry{Path: path, Size: info.Size(), Mode: fmt.Sprintf("%#o", info.Mode())}

		// generate checksum
		if info.Mode().IsRegular() {
			fhandle, err := os.Open(path)
			if err != nil {
				return err
			}
			defer fhandle.Close()

			hash := sha256.New()
			if _, err := io.Copy(hash, fhandle); err != nil {
				return err
			}

			entry.Checksum = fmt.Sprintf("sha256:%x", hash.Sum(nil))
		}

		entries = append(entries, entry)

		return nil
	})
	if err != nil {
		return err
	}

	if len(entries) == 0 {
		return fmt.Errorf("%w: no files found", errors.ErrNotFound)
	}

	content, err := json.Marshal(entries)
	if err != nil {
		return err
	}

	if err := os.WriteFile(output, content, 0o644); err != nil { //nolint:gosec,gomnd
		return err
	}

	log.Info().Int("count", len(entries)).Msg("files found during inventory")

	return nil
}

func ReadInventory(path string) (*Inventory, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var inv Inventory
	if err := json.Unmarshal(content, &inv.Entries); err != nil {
		return nil, err
	}

	return &inv, nil
}
