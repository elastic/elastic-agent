// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runner

import (
	"bufio"
	"bytes"
	"encoding/json"
)

type JSONTestEntry struct {
	Time    string `json:"Time"`
	Action  string `json:"Action"`
	Package string `json:"Package"`
	Test    string `json:"Test"`
	Output  string `json:"Output"`
}

func suffixJSONResults(content []byte, suffix string) ([]byte, error) {
	var result bytes.Buffer
	sc := bufio.NewScanner(bytes.NewReader(content))
	for sc.Scan() {
		var entry JSONTestEntry
		err := json.Unmarshal([]byte(sc.Text()), &entry)
		if err != nil {
			return nil, err
		}
		if entry.Package != "" {
			entry.Package += suffix
		}
		raw, err := json.Marshal(&entry)
		if err != nil {
			return nil, err
		}
		_, err = result.Write(raw)
		if err != nil {
			return nil, err
		}
	}
	return result.Bytes(), nil
}
