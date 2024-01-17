package distro

import (
	"fmt"

	"github.com/gabriel-vasile/mimetype"
	"github.com/rs/zerolog/log"
	"sigs.k8s.io/bom/pkg/spdx"
	"stackerbuild.io/stacker-bom/errors"
	"stackerbuild.io/stacker-bom/pkg/distro/apk"
	"stackerbuild.io/stacker-bom/pkg/distro/deb"
	"stackerbuild.io/stacker-bom/pkg/distro/rpm"
)

type Distro interface {
	InstalledPackages() (*spdx.Document, error)
}

func InstalledPackages(doc *spdx.Document) error {
	// check assuming deb
	deberr := deb.InstalledPackages(doc)
	if deberr == nil {
		return nil
	}

	// check assuming rpm
	rpmerr := rpm.InstalledPackages(doc)
	if rpmerr == nil {
		return nil
	}

	// check assuming apk
	apkerr := apk.InstalledPackages(doc)
	if apkerr == nil {
		return nil
	}

	log.Error().Err(apkerr).Msg("unable to get installed packages")

	return errors.ErrNotFound
}

func ParsePackage(input, author, organization, license, output string) error {
	mtype, err := mimetype.DetectFile(input)
	if err != nil {
		log.Error().Err(err).Msg("failed to detect mime-type")

		return err
	}

	log.Info().Str("path", input).Str("mime-type", mtype.String()).Msg("mime-type detected")

	switch mtype.String() {
	case "application/vnd.debian.binary-package":
		return deb.ParsePackage(input, output, author, organization, license)
	case "application/x-rpm":
		return rpm.ParsePackage(input, output, author, organization, license)
	case "application/gzip": // best effort
		return apk.ParsePackage(input, output, author, organization, license)
	default:
		return fmt.Errorf("%w: mime-type %s", errors.ErrUnsupported, mtype.String())
	}
}
