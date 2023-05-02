// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build local

package define

// runtimeAllowed returns true if the runtime matches a valid OS.
func (r Requirements) runtimeAllowed(os string, arch string, version string, distro string) bool {
	if len(r.OS) == 0 {
		// all allowed
		return true
	}
	for _, o := range r.OS {
		if o.Type != os {
			// not valid on this runtime
			continue
		}
		if o.Arch != "" && o.Arch != arch {
			// not allowed on specific architecture
			continue
		}
		if o.Version != "" && o.Version != version {
			// not allowed on specific version
			continue
		}
		if o.Distro != "" && o.Distro != distro {
			// not allowed on specific distro
			continue
		}
		// allowed
		return true
	}
	// made it this far, not allowed
	return false
}
