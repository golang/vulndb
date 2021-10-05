// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package internal

// Affects
type Affects struct {
	Vendor Vendor `json:"vendor"`
}

// CVEDataMeta
type CVEDataMeta struct {
	ASSIGNER string `json:"ASSIGNER"`
	ID       string `json:"ID"`
	STATE    string `json:"STATE"`
}

// Description
type Description struct {
	DescriptionData []LangString `json:"description_data"`
}

// LangString
type LangString struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// Problemtype
type Problemtype struct {
	ProblemtypeData []ProblemtypeDataItems `json:"problemtype_data"`
}

// ProblemtypeDataItems
type ProblemtypeDataItems struct {
	Description []LangString `json:"description"`
}

type VersionData struct {
	VersionData []VersionDataItems `json:"version_data"`
}

type ProductDataItem struct {
	ProductName string      `json:"product_name"`
	Version     VersionData `json:"version"`
}

// Product
type Product struct {
	ProductData []ProductDataItem `json:"product_data"`
}

// Reference
type Reference struct {
	URL string `json:"url"`
}

// References
type References struct {
	ReferenceData []Reference `json:"reference_data"`
}

// Vendor
type Vendor struct {
	VendorData []VendorDataItems `json:"vendor_data"`
}

// VendorDataItems
type VendorDataItems struct {
	Product    Product `json:"product"`
	VendorName string  `json:"vendor_name"`
}

// VersionDataItems
type VersionDataItems struct {
	VersionValue    string `json:"version_value"`
	VersionAffected string `json:"version_affected"`
}

// CVE
type CVE struct {
	DataType    string      `json:"data_type"`
	DataFormat  string      `json:"data_format"`
	DataVersion string      `json:"data_version"`
	CVEDataMeta CVEDataMeta `json:"CVE_data_meta"`

	Affects     Affects     `json:"affects"`
	Description Description `json:"description"`
	Problemtype Problemtype `json:"problemtype"`
	References  References  `json:"references"`
}
