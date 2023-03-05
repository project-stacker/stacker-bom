package distro

import (
	"archive/tar"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/minio/sha256-simd"
	"github.com/rs/zerolog/log"
	"pault.ag/go/debian/deb"
	k8spdx "sigs.k8s.io/bom/pkg/spdx"
)

func ParsePackage(path, author, organization, license string) error {
	debfile, _, err := deb.LoadFile(path)
	if err != nil {
		log.Error().Err(err).Str("path", path).Msg("unable to load package")

		return err
	}

	defer debfile.Close()

	kdoc := k8spdx.NewDocument()
	kdoc.Creator.Person = author
	kdoc.Creator.Organization = organization
	kdoc.Creator.Tool = []string{"stackerbuild.io/sbom"}

	pkg := &k8spdx.Package{
		Entity: k8spdx.Entity{
			Name: debfile.Control.Package,
		},
		Version: debfile.Control.Version.String(),
		Originator: struct {
			Person       string
			Organization string
		}{
			Person: debfile.Control.Maintainer,
		},
		LicenseDeclared: license,
	}

	if err := kdoc.AddPackage(pkg); err != nil {
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

		if hdr.Typeflag == tar.TypeDir {
			log.Warn().Str("name", hdr.Name).Msg("ignoring dir entry")

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

		cksum := sha256.Sum256(buf)

		log.Info().Str("name", hdr.Name).
			Int("size", bufsz).
			Str("cksum", fmt.Sprintf("SHA256:%s", hex.EncodeToString(cksum[:]))).
			Msg("file entry detected")

		file := &k8spdx.File{
			Entity: k8spdx.Entity{
				Name:     hdr.Name[1:],
				Checksum: map[string]string{"SHA256": hex.EncodeToString(cksum[:])},
			},
		}
		if err := pkg.AddFile(file); err != nil {
			log.Error().Err(err).Msg("unable to add file to package")

			return err
		}

		if strings.HasPrefix(hdr.Name, "./usr/share/doc/") && strings.HasSuffix(hdr.Name, "copyright") {
			log.Info().Str("path", hdr.Name).Msg("license/copyright found")
			pkg.LicenseComments = string(buf)
		}
	}

	spdxfile := path + ".k8s.spdx"
	if err := kdoc.Write(spdxfile); err != nil {
		log.Error().Err(err).Str("path", spdxfile).Msg("unable to write output")

		return err
	}

	return nil
}
