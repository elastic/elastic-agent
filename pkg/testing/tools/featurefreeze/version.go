package featurefreeze

//
// func AdjustVersion(v string) (string, error) {
// 	pv, err := version.ParseVersion(v)
// 	if err != nil {
// 		return "", fmt.Errorf("could not parse version %q: %w",
// 			v, err)
// 	}
//
// 	if pv.Major() == 8 && pv.Minor() == 11 {
// 		prev, err := pv.GetPreviousMinor()
// 		if err != nil {
// 			return "", fmt.Errorf("8.11 cannoit be used right now, "+
// 				"failed getting previous minor: %w", err)
// 		}
// 		v = prev.String()
// 	}
//
// 	return v, nil
// }

//
// // ChangePackageVersion changes the package version of the Agent to 'version'.
// //
// // After feature freeze the agent has the version of the next minor but there is
// // a few days of lag until the snapshot is produced to test against. To get
// // around this the tests continue to provision the previous minor and the agent
// // package version is replaced to report the previous minor version as well.
// // As of the time of writing fleet server will consider versions greater than
// // its own to be unsupported. This allows the newer agent to enroll.
// //
// // This function is meant to be temporary. Fleet server should be modified to
// // allow the next minor version to connect to get around this in a more
// // sustainable way.
// func ChangePackageVersion(workDir, version string) error {
// 	installFS := os.DirFS(workDir)
// 	var matches []string
// 	err := fs.WalkDir(installFS, ".", func(path string, d fs.DirEntry, err error) error {
// 		if err != nil {
// 			return err
// 		}
//
// 		if d.Name() == version2.PackageVersionFileName {
// 			matches = append(matches, path)
// 		}
// 		return nil
// 	})
// 	if err != nil {
// 		return err
// 	}
//
// 	for _, m := range matches {
// 		versionFile := filepath.Join(workDir, m)
//
// 		err = os.WriteFile(versionFile, []byte(version), 0666)
// 		if err != nil {
// 			return fmt.Errorf("could not write package-version file %q: %w",
// 				versionFile, err)
// 		}
// 	}
//
// 	return nil
// }
