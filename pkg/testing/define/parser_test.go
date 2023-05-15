// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package define

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateRequireFromFunc_ValidAssign(t *testing.T) {
	code := `
package example

import (
	"testing"

	"github.com/elastic/elastic-agent/pkg/testing/define"
)

func TestExample(t *testing.T) {
	info := define.Require(t, define.Requirements{})
}
`

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "example.go", code, parser.DeclarationErrors|parser.ParseComments)
	require.NoError(t, err)
	require.Len(t, f.Decls, 2)

	fn := f.Decls[1].(*ast.FuncDecl)
	require.True(t, validateRequireFromFunc(fn))
}

func TestValidateRequireFromFunc_ValidCall(t *testing.T) {
	code := `
package example

import (
	"testing"

	"github.com/elastic/elastic-agent/pkg/testing/define"
)

func TestExample(t *testing.T) {
	define.Require(t, define.Requirements{})
}
`

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "example.go", code, parser.DeclarationErrors|parser.ParseComments)
	require.NoError(t, err)
	require.Len(t, f.Decls, 2)

	fn := f.Decls[1].(*ast.FuncDecl)
	require.True(t, validateRequireFromFunc(fn))
}

func TestValidateRequireFromFunc_ValidSuite(t *testing.T) {
	code := `
package example

import (
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/elastic/elastic-agent/pkg/testing/define"
)


type ExampleTestSuite struct {
	suite.Suite
}

func (s *ExampleTestSuite) TestExample() {

}

func TestExampleSuite(t *testing.T) {
	define.Require(t, define.Requirements{})
	suite.Run(t, new(ExampleTestSuite))
}
`

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "example.go", code, parser.DeclarationErrors|parser.ParseComments)
	require.NoError(t, err)
	require.Len(t, f.Decls, 4)

	fn := f.Decls[2].(*ast.FuncDecl) // func (s *ExampleTestSuite) TestExample()
	require.False(t, validateRequireFromFunc(fn))
	fn = f.Decls[3].(*ast.FuncDecl) // func TestExampleSuite(t *testing.T)
	require.True(t, validateRequireFromFunc(fn))
}

func TestValidateRequireFromFunc_InvalidMissing(t *testing.T) {
	code := `
package example

import "testing"

func TestExample(t *testing.T) {
}
`

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "example.go", code, parser.DeclarationErrors|parser.ParseComments)
	require.NoError(t, err)
	require.Len(t, f.Decls, 2)

	fn := f.Decls[1].(*ast.FuncDecl)
	require.False(t, validateRequireFromFunc(fn))
}

func TestValidateRequireFromFunc_InvalidNotFirst(t *testing.T) {
	code := `
package example

import (
	"testing"

	"github.com/elastic/elastic-agent/pkg/testing/define"
)

func TestExample(t *testing.T) {
	t.Skip("define.Require should be first")
	define.Require(t, define.Requirements{})
}
`

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "example.go", code, parser.DeclarationErrors|parser.ParseComments)
	require.NoError(t, err)
	require.Len(t, f.Decls, 2)

	fn := f.Decls[1].(*ast.FuncDecl)
	require.False(t, validateRequireFromFunc(fn))
}
