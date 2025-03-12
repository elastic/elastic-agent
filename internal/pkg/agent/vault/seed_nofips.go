// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !requirefips

package vault

import "errors"

func getSeed(path string) ([]byte, int, error) {
	b, errV1 := getSeedV1(path)
	if errV1 == nil {
		return b, saltSizeV1, nil
	}
	b, saltSize, errV2 := getSeedV2(path)
	if errV2 == nil {
		return b, saltSize, nil
	}
	return nil, 0, errors.Join(errV1, errV2)
}
