// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package define

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"strings"
)

// Test is a found test with its requirements.
type Test struct {
	Name         string
	Requirements Requirements
}

// File is a file and its set of tests it contains.
type File struct {
	// Name of the file.
	Name string
	// Tests are the tests contained in the file.
	Tests []Test
}

// Package is a package of files with tests.
type Package struct {
	// Name of the package.
	Name string
	// File is the name of the file.
	Files []File
}

// ValidateDir parses a directory and ensures that every test first function call is to `define.Require`.
func ValidateDir(dir string) error {
	fset := token.NewFileSet()
	pkgs, first := parser.ParseDir(fset, dir, func(info fs.FileInfo) bool {
		return strings.HasSuffix(info.Name(), "_test.go")
	}, parser.ParseComments)
	if first != nil {
		return first
	}
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, d := range file.Decls {
				fn, ok := d.(*ast.FuncDecl)
				if ok && strings.HasPrefix(fn.Name.Name, "Test") && fn.Recv == nil {
					if !validateRequireFromFunc(fn) {
						return fmt.Errorf("test %s first statement must be a function call to define.Require", fn.Name.Name)
					}
				}
			}
		}
	}
	return nil
}

func validateRequireFromFunc(fn *ast.FuncDecl) bool {
	for _, stmt := range fn.Body.List {
		switch st := stmt.(type) {
		case *ast.AssignStmt:
			switch rh := st.Rhs[0].(type) {
			case *ast.CallExpr:
				return validateRequireFromCall(rh)
			}
		case *ast.ExprStmt:
			switch xt := st.X.(type) {
			case *ast.CallExpr:
				return validateRequireFromCall(xt)
			}
		}
		// must be the first call
		return false
	}
	return false
}

func validateRequireFromCall(call *ast.CallExpr) bool {
	se, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	xi, ok := se.X.(*ast.Ident)
	if !ok {
		return false
	}
	return xi.Name == "define" && se.Sel.Name == "Require"
}
