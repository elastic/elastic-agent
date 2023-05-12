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
	if len(fn.Body.List) < 1 {
		return false
	}
	stmt := fn.Body.List[0]
	switch st := stmt.(type) {
	// info := define.Require(...)
	case *ast.AssignStmt:
		switch rh := st.Rhs[0].(type) {
		case *ast.CallExpr:
			return validateRequireFromCall(rh)
		}
	// define.Require(...)
	case *ast.ExprStmt:
		switch xt := st.X.(type) {
		case *ast.CallExpr:
			return validateRequireFromCall(xt)
		}
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
