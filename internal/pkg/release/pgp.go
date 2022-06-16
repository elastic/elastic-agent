// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package release

import _ "embed" // embed PGP key

// pgp bytes is a packed in public gpg key
// go:embed ../../../dev-tools/resources/GPG-KEY-elastic.pub
var pgpBytes []byte

// PGP return pgpbytes and a flag describing whether or not no pgp is valid.
func PGP() (bool, []byte) {
	return allowEmptyPgp == "true", pgpBytes
}
