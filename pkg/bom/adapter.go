package bom

import (
	"path/filepath"

	"github.com/spdx/tools-golang/spdx/v2/v2_3"
	"sigs.k8s.io/bom/pkg/spdx"
)

func ConvertFromSyftFile(fil *v2_3.File) *spdx.File {
	kfil := &spdx.File{
		Entity: spdx.Entity{
			ID:               string(fil.FileSPDXIdentifier),
			Name:             fil.FileName,
			CopyrightText:    fil.FileCopyrightText,
			LicenseConcluded: fil.LicenseConcluded,
			LicenseComments:  fil.LicenseComments,
			Checksum:         map[string]string{},
		},
		FileType: fil.FileTypes,
	}

	for _, lic := range fil.LicenseInfoInFiles {
		if lic == "" {
			continue
		}

		if kfil.LicenseInfoInFile == "" {
			kfil.LicenseInfoInFile = lic
		} else {
			kfil.LicenseInfoInFile += " " + lic
		}
	}

	for _, cksum := range fil.Checksums {
		kfil.Entity.Checksum[string(cksum.Algorithm)] = cksum.Value
	}

	return kfil
}

func ConvertFromSyftPackage(path string, pkg *v2_3.Package) *spdx.Package {
	kpkg := &spdx.Package{
		Entity: spdx.Entity{
			ID:               string(pkg.PackageSPDXIdentifier),
			SourceFile:       pkg.PackageSourceInfo,
			Name:             pkg.PackageName,
			DownloadLocation: pkg.PackageDownloadLocation,
			CopyrightText:    pkg.PackageCopyrightText,
			FileName:         pkg.PackageFileName,
			LicenseConcluded: pkg.PackageLicenseConcluded,
			LicenseComments:  pkg.PackageLicenseComments,
			Checksum:         map[string]string{},
		},
		FilesAnalyzed:   pkg.FilesAnalyzed,
		LicenseDeclared: pkg.PackageLicenseDeclared,
		Version:         pkg.PackageVersion,
		Comment:         pkg.PackageComment,
		HomePage:        pkg.PackageHomePage,
		PrimaryPurpose:  pkg.PrimaryPackagePurpose,
		Supplier: struct {
			Person       string
			Organization string
		}{},
		Originator: struct {
			Person       string
			Organization string
		}{},
		ExternalRefs: []spdx.ExternalRef{},
	}

	if len(pkg.PackageLicenseInfoFromFiles) > 0 {
		kpkg.LicenseInfoFromFiles = pkg.PackageLicenseInfoFromFiles
	}

	for _, cksum := range pkg.PackageChecksums {
		kpkg.Entity.Checksum[string(cksum.Algorithm)] = cksum.Value
	}

	if pkg.PackageSupplier != nil {
		switch pkg.PackageSupplier.SupplierType {
		case "Person":
			kpkg.Supplier.Person = pkg.PackageSupplier.Supplier
		case "Organization":
			kpkg.Supplier.Organization = pkg.PackageSupplier.Supplier
		}
	}

	if pkg.PackageOriginator != nil {
		switch pkg.PackageOriginator.OriginatorType {
		case "Person":
			kpkg.Originator.Person = pkg.PackageOriginator.Originator
		case "Organization":
			kpkg.Originator.Organization = pkg.PackageOriginator.Originator
		}
	}

	for _, rel := range pkg.PackageExternalReferences {
		kpkg.ExternalRefs = append(kpkg.ExternalRefs,
			spdx.ExternalRef{
				Category: rel.Category,
				Type:     rel.RefType,
				Locator:  rel.Locator,
			})
	}

	for _, fil := range pkg.Files {
		if path != "" {
			fil.FileName = filepath.Join(path, fil.FileName)
		}
		_ = kpkg.AddFile(ConvertFromSyftFile(fil))
	}

	return kpkg
}
