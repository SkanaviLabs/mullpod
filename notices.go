// Copyright (c) 2026 Stanislav Yurin, AI Security Engineering LLC dba Skanavi
// SPDX-License-Identifier: MIT

package main

import _ "embed"

// Embed the license texts so a standalone binary can reproduce the copyright
// and license notices required by the project and its dependencies.
//
//go:embed LICENSE
var licenseText string

//go:embed THIRD_PARTY_NOTICES.md
var thirdPartyNotices string
