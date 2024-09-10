// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package gotool

// Mod is the command go mod.
var Mod = goMod{
	Download: modCommand{"download"}.run,
	Init:     modCommand{"init"}.run,
	Tidy:     modCommand{"tidy"}.run,
	Verify:   modCommand{"verify"}.run,
	Vendor:   modCommand{"vendor"}.run,
}

type modCommand struct {
	method string
}

func (cmd modCommand) run(opts ...ArgOpt) error {
	o := make([]ArgOpt, len(opts)+1)
	o[0] = posArg(cmd.method)
	for i, opt := range opts {
		o[i+1] = opt
	}
	args := buildArgs(o)
	return runVGo("mod", args)
}

type goMod struct {
	Download modDownload
	Init     modInit
	Tidy     modTidy
	Verify   modVerify
	Vendor   modVendor
}

// modDownload cleans the go.mod file
type modDownload func(opts ...ArgOpt) error

// modInit initializes a new go module in folder.
type modInit func(opts ...ArgOpt) error

// modTidy cleans the go.mod file
type modTidy func(opts ...ArgOpt) error

// modVerify check that deps have the expected content.
type modVerify func(opts ...ArgOpt) error

// modVendor downloads and copies dependencies under the folder vendor.
type modVendor func(opts ...ArgOpt) error
