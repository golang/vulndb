// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package cveschema contains the schema for a CVE, as derived from
// https://github.com/CVEProject/automation-working-group/tree/master/cve_json_schema.
package cveschema

const (
	// StateReserved is the initial state for a CVE Record; when the associated
	// CVE ID is Reserved by a CNA.
	StateReserved = "RESERVED"

	// StatePublished is when a CNA populates the data associated with a CVE ID
	// as a CVE Record, the state of the CVE Record is Published. The
	// associated data must contain an identification number (CVE ID), a prose
	// description, and at least one public reference.
	StatePublished = "PUBLISHED"

	// StateRejected is when the CVE ID and associated CVE Record should no
	// longer be used, the CVE Record is placed in the Rejected state. A Rejected
	// CVE Record remains on the CVE List so that users can know when it is
	// invalid.
	StateRejected = "REJECTED"
)

// CVE represents a "Common Vulnerabilities and Exposures" record, which is
// associated with a CVE ID and provided by a CNA.
//
// A CVE corresponds to a flaw in a software, firmware, hardware, or service
// component resulting from a weakness that can be exploited, causing a negative
// impact to the confidentiality, integrity, or availability of an impacted
// component or components.
type CVE struct {
	// DataType identifies what kind of data is held in this JSON file. This is
	// mandatory and designed to prevent problems with attempting to detect
	// what kind of file this is. Valid values for this string are CVE, CNA,
	// CVEMENTOR.
	DataType string `json:"data_type"`

	// DataFormat identifies what data format is used in this JSON file. This
	// is mandatory and designed to prevent problems with attempting to detect
	// what format of data is used. Valid values for this string are MITRE, it can
	// also be user defined (e.g. for internal use).
	DataFormat string `json:"data_format"`

	// DataVersion identifies which version of the data format is in use. This
	// is mandatory and designed to prevent problems with attempting to detect
	// what format of data is used.
	DataVersion string `json:"data_version"`

	// CVEDataMeta is meta data about the CVE ID such as the CVE ID, who
	// requested it, who assigned it, when it was requested, when it was assigned,
	// the current state (PUBLIC, REJECT, etc.) and so on.
	CVEDataMeta CVEDataMeta `json:"CVE_data_meta"`

	// Affects is the root level container for affected vendors and in turn
	// their affected technologies, products, hardware, etc. It only goes in
	// the root level.
	Affects Affects `json:"affects"`

	// Description is a description of the issue. It can exist in the root
	// level or within virtually any other container, the intent being that for
	// example different products, and configurations may result in different
	// impacts and thus descriptions of the issue.
	Description Description `json:"description"`

	// ProblemType is problem type information (e.g. CWE identifier).
	Problemtype Problemtype `json:"problemtype"`

	// References is reference data in the form of URLs or file objects
	// (uuencoded and embedded within the JSON file, exact format to be
	// decided, e.g. we may require a compressed format so the objects require
	// unpacking before they are "dangerous").
	References References `json:"references"`
}

// CVEDataMeta is meta data about the CVE ID such as the CVE ID, who requested
// it, who assigned it, when it was requested, when it was assigned, the
// current state (PUBLIC, REJECT, etc.) and so on.
type CVEDataMeta struct {
	ASSIGNER string `json:"ASSIGNER"`
	ID       string `json:"ID"`
	STATE    string `json:"STATE"`
}

// Affects is the root level container for affected vendors and in turn their
// affected technologies, products, hardware, etc. It only goes in the root
// level.
type Affects struct {
	Vendor Vendor `json:"vendor"`
}

// Description is a description of the issue. It can exist in the root level or
// within virtually any other container, the intent being that for example
// different products, and configurations may result in different impacts and
// thus descriptions of the issue.
//
// The description could include:
//
// An explanation of an attack type using the vulnerability;
// The impact of the vulnerability;
// The software components within a software product that are affected by the
// vulnerability; and
// Any attack vectors that can make use of the vulnerability.
//
// Descriptions often follow this template:
//
//      [PROBLEM TYPE] in [PRODUCT/VERSION] causes [IMPACT] when [ATTACK]
//
// where impact and attack are arbitrary terms that should be relevant to the
// nature of the vulnerability.
type Description struct {
	DescriptionData []LangString `json:"description_data"`
}

// ProblemType is problem type information (e.g. CWE identifier).
//
// It can include an arbitrary summary of the problem, though Common Weakness
// Enumerations (CWEs) are a standard to use in this field.
type Problemtype struct {
	ProblemtypeData []ProblemtypeDataItems `json:"problemtype_data"`
}

// ProblemtypeDataItems are the entries in a ProblemType.
type ProblemtypeDataItems struct {
	Description []LangString `json:"description"`
}

// LangString is a JSON data type containing the language that a description is
// written in and the text string.
type LangString struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// References is reference data in the form of URLs or file objects (uuencoded
// and embedded within the JSON file, exact format to be decided, e.g. we may
// require a compressed format so the objects require unpacking before they are
// "dangerous").
type References struct {
	ReferenceData []Reference `json:"reference_data"`
}

// A reference is a URL pointing to a world-wide-web-based resource. For
// CSV and flat-file formats, they should be separated by a space. References
// should point to content that is relevant to the vulnerability and include at
// least all the details included in the CVE entry. Ideally, references should
// point to content that includes the CVE ID itself whenever possible. References
// must also be publicly available, as described in Section 2.1.1 of the CVE
// Numbering Authorities (CNA) Rules.
type Reference struct {
	URL string `json:"url"`
}

// Vendor is the container for affected vendors, it only goes in the affects
// container.
type Vendor struct {
	// VendorData is an array of version values (vulnerable and not); we use an
	// array so that different entities can make statements about the same
	// vendor and they are separate (if we used a JSON object we'd essentially
	// be keying on the vendor name and they would have to overlap). Also this
	// allows things like data_version or description to be applied directly to
	// the vendor entry.
	VendorData []VendorDataItems `json:"vendor_data"`
}

// VendorDataItems represents a single vendor name and product.
type VendorDataItems struct {
	Product    Product `json:"product"`
	VendorName string  `json:"vendor_name"`
}

// Product is the container for affected technologies, products, hardware, etc.
//
// As a general guideline, the product should include the vendor, developer, or
// project name as well as the name of the actual software or hardware in which
// the vulnerability exists.
type Product struct {
	// ProductData is an array of version values (vulnerable and not); we use
	// an array so that we can make multiple statements about the same product and
	// they are separate (if we used a JSON object we'd essentially be keying on
	// the product name and they would have to overlap). Also this allows things
	// like data_version or description to be applied directly to the product
	// entry.
	ProductData []ProductDataItem `json:"product_data"`
}

// ProductDataItem represents a single product name and version that belongs to
// a product container.
type ProductDataItem struct {
	ProductName string      `json:"product_name"`
	Version     VersionData `json:"version"`
}

// VersionData is an array of version values (vulnerable and not); we use an
// array so that we can make multiple statements about the same version and they
// are separate (if we used a JSON object we'd essentially be keying on the
// version name/number and they would have to overlap). Also this allows things
// like data_version or description to be applied directly to the product entry.
// This also allows more complex statements such as "Product X between versions
// 10.2 and 10.8" to be put in a machine-readable format. As well since multiple
// statements can be used multiple branches of the same product can be defined
// here.
type VersionData struct {
	VersionData []VersionDataItems `json:"version_data"`
}

// VersionDataItems represents a version, the date of release, or whatever
// indicator that is used by vendors, developers, or projects to differentiate
// between releases. The version can be described with specific version
// numbers, ranges of versions, or “all versions before/after” a version number or
// date.
type VersionDataItems struct {
	VersionValue    string `json:"version_value"`
	VersionAffected string `json:"version_affected"`
}
