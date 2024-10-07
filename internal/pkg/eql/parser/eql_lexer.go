// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Code generated from Eql.g4 by ANTLR 4.13.1. DO NOT EDIT.

package parser

import (
	"fmt"
	"sync"
	"unicode"

	"github.com/antlr4-go/antlr/v4"
)

// Suppress unused import error
var _ = fmt.Printf
var _ = sync.Once{}
var _ = unicode.IsLetter

type EqlLexer struct {
	*antlr.BaseLexer
	channelNames []string
	modeNames    []string
	// TODO: EOF string
}

var EqlLexerLexerStaticData struct {
	once                   sync.Once
	serializedATN          []int32
	ChannelNames           []string
	ModeNames              []string
	LiteralNames           []string
	SymbolicNames          []string
	RuleNames              []string
	PredictionContextCache *antlr.PredictionContextCache
	atn                    *antlr.ATN
	decisionToDFA          []*antlr.DFA
}

func eqllexerLexerInit() {
	staticData := &EqlLexerLexerStaticData
	staticData.ChannelNames = []string{
		"DEFAULT_TOKEN_CHANNEL", "HIDDEN",
	}
	staticData.ModeNames = []string{
		"DEFAULT_MODE",
	}
	staticData.LiteralNames = []string{
		"", "'|'", "','", "':'", "'=='", "'!='", "'>'", "'<'", "'>='", "'<='",
		"'+'", "'-'", "'*'", "'/'", "'%'", "", "", "", "", "", "", "", "", "",
		"", "", "", "'('", "')'", "'['", "']'", "'{'", "'}'", "'$${'", "'${'",
	}
	staticData.SymbolicNames = []string{
		"", "", "", "", "EQ", "NEQ", "GT", "LT", "GTE", "LTE", "ADD", "SUB",
		"MUL", "DIV", "MOD", "AND", "OR", "TRUE", "FALSE", "FLOAT", "NUMBER",
		"WHITESPACE", "NOT", "NAME", "VNAME", "STEXT", "DTEXT", "LPAR", "RPAR",
		"LARR", "RARR", "LDICT", "RDICT", "BEGIN_EVARIABLE", "BEGIN_VARIABLE",
	}
	staticData.RuleNames = []string{
		"T__0", "T__1", "T__2", "EQ", "NEQ", "GT", "LT", "GTE", "LTE", "ADD",
		"SUB", "MUL", "DIV", "MOD", "AND", "OR", "TRUE", "FALSE", "FLOAT", "NUMBER",
		"WHITESPACE", "NOT", "NAME", "VNAME", "STEXT", "DTEXT", "LPAR", "RPAR",
		"LARR", "RARR", "LDICT", "RDICT", "BEGIN_EVARIABLE", "BEGIN_VARIABLE",
	}
	staticData.PredictionContextCache = antlr.NewPredictionContextCache()
	staticData.serializedATN = []int32{
		4, 0, 34, 234, 6, -1, 2, 0, 7, 0, 2, 1, 7, 1, 2, 2, 7, 2, 2, 3, 7, 3, 2,
		4, 7, 4, 2, 5, 7, 5, 2, 6, 7, 6, 2, 7, 7, 7, 2, 8, 7, 8, 2, 9, 7, 9, 2,
		10, 7, 10, 2, 11, 7, 11, 2, 12, 7, 12, 2, 13, 7, 13, 2, 14, 7, 14, 2, 15,
		7, 15, 2, 16, 7, 16, 2, 17, 7, 17, 2, 18, 7, 18, 2, 19, 7, 19, 2, 20, 7,
		20, 2, 21, 7, 21, 2, 22, 7, 22, 2, 23, 7, 23, 2, 24, 7, 24, 2, 25, 7, 25,
		2, 26, 7, 26, 2, 27, 7, 27, 2, 28, 7, 28, 2, 29, 7, 29, 2, 30, 7, 30, 2,
		31, 7, 31, 2, 32, 7, 32, 2, 33, 7, 33, 1, 0, 1, 0, 1, 1, 1, 1, 1, 2, 1,
		2, 1, 3, 1, 3, 1, 3, 1, 4, 1, 4, 1, 4, 1, 5, 1, 5, 1, 6, 1, 6, 1, 7, 1,
		7, 1, 7, 1, 8, 1, 8, 1, 8, 1, 9, 1, 9, 1, 10, 1, 10, 1, 11, 1, 11, 1, 12,
		1, 12, 1, 13, 1, 13, 1, 14, 1, 14, 1, 14, 1, 14, 1, 14, 1, 14, 3, 14, 108,
		8, 14, 1, 15, 1, 15, 1, 15, 1, 15, 3, 15, 114, 8, 15, 1, 16, 1, 16, 1,
		16, 1, 16, 1, 16, 1, 16, 1, 16, 1, 16, 3, 16, 124, 8, 16, 1, 17, 1, 17,
		1, 17, 1, 17, 1, 17, 1, 17, 1, 17, 1, 17, 1, 17, 1, 17, 3, 17, 136, 8,
		17, 1, 18, 3, 18, 139, 8, 18, 1, 18, 4, 18, 142, 8, 18, 11, 18, 12, 18,
		143, 1, 18, 1, 18, 4, 18, 148, 8, 18, 11, 18, 12, 18, 149, 1, 19, 3, 19,
		153, 8, 19, 1, 19, 4, 19, 156, 8, 19, 11, 19, 12, 19, 157, 1, 20, 4, 20,
		161, 8, 20, 11, 20, 12, 20, 162, 1, 20, 1, 20, 1, 21, 1, 21, 1, 21, 1,
		21, 1, 21, 1, 21, 3, 21, 173, 8, 21, 1, 22, 1, 22, 5, 22, 177, 8, 22, 10,
		22, 12, 22, 180, 9, 22, 1, 23, 4, 23, 183, 8, 23, 11, 23, 12, 23, 184,
		1, 23, 1, 23, 4, 23, 189, 8, 23, 11, 23, 12, 23, 190, 5, 23, 193, 8, 23,
		10, 23, 12, 23, 196, 9, 23, 1, 24, 1, 24, 5, 24, 200, 8, 24, 10, 24, 12,
		24, 203, 9, 24, 1, 24, 1, 24, 1, 25, 1, 25, 5, 25, 209, 8, 25, 10, 25,
		12, 25, 212, 9, 25, 1, 25, 1, 25, 1, 26, 1, 26, 1, 27, 1, 27, 1, 28, 1,
		28, 1, 29, 1, 29, 1, 30, 1, 30, 1, 31, 1, 31, 1, 32, 1, 32, 1, 32, 1, 32,
		1, 33, 1, 33, 1, 33, 0, 0, 34, 1, 1, 3, 2, 5, 3, 7, 4, 9, 5, 11, 6, 13,
		7, 15, 8, 17, 9, 19, 10, 21, 11, 23, 12, 25, 13, 27, 14, 29, 15, 31, 16,
		33, 17, 35, 18, 37, 19, 39, 20, 41, 21, 43, 22, 45, 23, 47, 24, 49, 25,
		51, 26, 53, 27, 55, 28, 57, 29, 59, 30, 61, 31, 63, 32, 65, 33, 67, 34,
		1, 0, 8, 1, 0, 45, 45, 1, 0, 48, 57, 3, 0, 9, 10, 13, 13, 32, 32, 3, 0,
		65, 90, 95, 95, 97, 122, 4, 0, 48, 57, 65, 90, 95, 95, 97, 122, 5, 0, 45,
		45, 47, 57, 65, 90, 95, 95, 97, 122, 3, 0, 10, 10, 13, 13, 39, 39, 3, 0,
		10, 10, 13, 13, 34, 34, 250, 0, 1, 1, 0, 0, 0, 0, 3, 1, 0, 0, 0, 0, 5,
		1, 0, 0, 0, 0, 7, 1, 0, 0, 0, 0, 9, 1, 0, 0, 0, 0, 11, 1, 0, 0, 0, 0, 13,
		1, 0, 0, 0, 0, 15, 1, 0, 0, 0, 0, 17, 1, 0, 0, 0, 0, 19, 1, 0, 0, 0, 0,
		21, 1, 0, 0, 0, 0, 23, 1, 0, 0, 0, 0, 25, 1, 0, 0, 0, 0, 27, 1, 0, 0, 0,
		0, 29, 1, 0, 0, 0, 0, 31, 1, 0, 0, 0, 0, 33, 1, 0, 0, 0, 0, 35, 1, 0, 0,
		0, 0, 37, 1, 0, 0, 0, 0, 39, 1, 0, 0, 0, 0, 41, 1, 0, 0, 0, 0, 43, 1, 0,
		0, 0, 0, 45, 1, 0, 0, 0, 0, 47, 1, 0, 0, 0, 0, 49, 1, 0, 0, 0, 0, 51, 1,
		0, 0, 0, 0, 53, 1, 0, 0, 0, 0, 55, 1, 0, 0, 0, 0, 57, 1, 0, 0, 0, 0, 59,
		1, 0, 0, 0, 0, 61, 1, 0, 0, 0, 0, 63, 1, 0, 0, 0, 0, 65, 1, 0, 0, 0, 0,
		67, 1, 0, 0, 0, 1, 69, 1, 0, 0, 0, 3, 71, 1, 0, 0, 0, 5, 73, 1, 0, 0, 0,
		7, 75, 1, 0, 0, 0, 9, 78, 1, 0, 0, 0, 11, 81, 1, 0, 0, 0, 13, 83, 1, 0,
		0, 0, 15, 85, 1, 0, 0, 0, 17, 88, 1, 0, 0, 0, 19, 91, 1, 0, 0, 0, 21, 93,
		1, 0, 0, 0, 23, 95, 1, 0, 0, 0, 25, 97, 1, 0, 0, 0, 27, 99, 1, 0, 0, 0,
		29, 107, 1, 0, 0, 0, 31, 113, 1, 0, 0, 0, 33, 123, 1, 0, 0, 0, 35, 135,
		1, 0, 0, 0, 37, 138, 1, 0, 0, 0, 39, 152, 1, 0, 0, 0, 41, 160, 1, 0, 0,
		0, 43, 172, 1, 0, 0, 0, 45, 174, 1, 0, 0, 0, 47, 182, 1, 0, 0, 0, 49, 197,
		1, 0, 0, 0, 51, 206, 1, 0, 0, 0, 53, 215, 1, 0, 0, 0, 55, 217, 1, 0, 0,
		0, 57, 219, 1, 0, 0, 0, 59, 221, 1, 0, 0, 0, 61, 223, 1, 0, 0, 0, 63, 225,
		1, 0, 0, 0, 65, 227, 1, 0, 0, 0, 67, 231, 1, 0, 0, 0, 69, 70, 5, 124, 0,
		0, 70, 2, 1, 0, 0, 0, 71, 72, 5, 44, 0, 0, 72, 4, 1, 0, 0, 0, 73, 74, 5,
		58, 0, 0, 74, 6, 1, 0, 0, 0, 75, 76, 5, 61, 0, 0, 76, 77, 5, 61, 0, 0,
		77, 8, 1, 0, 0, 0, 78, 79, 5, 33, 0, 0, 79, 80, 5, 61, 0, 0, 80, 10, 1,
		0, 0, 0, 81, 82, 5, 62, 0, 0, 82, 12, 1, 0, 0, 0, 83, 84, 5, 60, 0, 0,
		84, 14, 1, 0, 0, 0, 85, 86, 5, 62, 0, 0, 86, 87, 5, 61, 0, 0, 87, 16, 1,
		0, 0, 0, 88, 89, 5, 60, 0, 0, 89, 90, 5, 61, 0, 0, 90, 18, 1, 0, 0, 0,
		91, 92, 5, 43, 0, 0, 92, 20, 1, 0, 0, 0, 93, 94, 5, 45, 0, 0, 94, 22, 1,
		0, 0, 0, 95, 96, 5, 42, 0, 0, 96, 24, 1, 0, 0, 0, 97, 98, 5, 47, 0, 0,
		98, 26, 1, 0, 0, 0, 99, 100, 5, 37, 0, 0, 100, 28, 1, 0, 0, 0, 101, 102,
		5, 97, 0, 0, 102, 103, 5, 110, 0, 0, 103, 108, 5, 100, 0, 0, 104, 105,
		5, 65, 0, 0, 105, 106, 5, 78, 0, 0, 106, 108, 5, 68, 0, 0, 107, 101, 1,
		0, 0, 0, 107, 104, 1, 0, 0, 0, 108, 30, 1, 0, 0, 0, 109, 110, 5, 111, 0,
		0, 110, 114, 5, 114, 0, 0, 111, 112, 5, 79, 0, 0, 112, 114, 5, 82, 0, 0,
		113, 109, 1, 0, 0, 0, 113, 111, 1, 0, 0, 0, 114, 32, 1, 0, 0, 0, 115, 116,
		5, 116, 0, 0, 116, 117, 5, 114, 0, 0, 117, 118, 5, 117, 0, 0, 118, 124,
		5, 101, 0, 0, 119, 120, 5, 84, 0, 0, 120, 121, 5, 82, 0, 0, 121, 122, 5,
		85, 0, 0, 122, 124, 5, 69, 0, 0, 123, 115, 1, 0, 0, 0, 123, 119, 1, 0,
		0, 0, 124, 34, 1, 0, 0, 0, 125, 126, 5, 102, 0, 0, 126, 127, 5, 97, 0,
		0, 127, 128, 5, 108, 0, 0, 128, 129, 5, 115, 0, 0, 129, 136, 5, 101, 0,
		0, 130, 131, 5, 70, 0, 0, 131, 132, 5, 65, 0, 0, 132, 133, 5, 76, 0, 0,
		133, 134, 5, 83, 0, 0, 134, 136, 5, 69, 0, 0, 135, 125, 1, 0, 0, 0, 135,
		130, 1, 0, 0, 0, 136, 36, 1, 0, 0, 0, 137, 139, 7, 0, 0, 0, 138, 137, 1,
		0, 0, 0, 138, 139, 1, 0, 0, 0, 139, 141, 1, 0, 0, 0, 140, 142, 7, 1, 0,
		0, 141, 140, 1, 0, 0, 0, 142, 143, 1, 0, 0, 0, 143, 141, 1, 0, 0, 0, 143,
		144, 1, 0, 0, 0, 144, 145, 1, 0, 0, 0, 145, 147, 5, 46, 0, 0, 146, 148,
		7, 1, 0, 0, 147, 146, 1, 0, 0, 0, 148, 149, 1, 0, 0, 0, 149, 147, 1, 0,
		0, 0, 149, 150, 1, 0, 0, 0, 150, 38, 1, 0, 0, 0, 151, 153, 7, 0, 0, 0,
		152, 151, 1, 0, 0, 0, 152, 153, 1, 0, 0, 0, 153, 155, 1, 0, 0, 0, 154,
		156, 7, 1, 0, 0, 155, 154, 1, 0, 0, 0, 156, 157, 1, 0, 0, 0, 157, 155,
		1, 0, 0, 0, 157, 158, 1, 0, 0, 0, 158, 40, 1, 0, 0, 0, 159, 161, 7, 2,
		0, 0, 160, 159, 1, 0, 0, 0, 161, 162, 1, 0, 0, 0, 162, 160, 1, 0, 0, 0,
		162, 163, 1, 0, 0, 0, 163, 164, 1, 0, 0, 0, 164, 165, 6, 20, 0, 0, 165,
		42, 1, 0, 0, 0, 166, 167, 5, 78, 0, 0, 167, 168, 5, 79, 0, 0, 168, 173,
		5, 84, 0, 0, 169, 170, 5, 110, 0, 0, 170, 171, 5, 111, 0, 0, 171, 173,
		5, 116, 0, 0, 172, 166, 1, 0, 0, 0, 172, 169, 1, 0, 0, 0, 173, 44, 1, 0,
		0, 0, 174, 178, 7, 3, 0, 0, 175, 177, 7, 4, 0, 0, 176, 175, 1, 0, 0, 0,
		177, 180, 1, 0, 0, 0, 178, 176, 1, 0, 0, 0, 178, 179, 1, 0, 0, 0, 179,
		46, 1, 0, 0, 0, 180, 178, 1, 0, 0, 0, 181, 183, 7, 5, 0, 0, 182, 181, 1,
		0, 0, 0, 183, 184, 1, 0, 0, 0, 184, 182, 1, 0, 0, 0, 184, 185, 1, 0, 0,
		0, 185, 194, 1, 0, 0, 0, 186, 188, 5, 46, 0, 0, 187, 189, 7, 5, 0, 0, 188,
		187, 1, 0, 0, 0, 189, 190, 1, 0, 0, 0, 190, 188, 1, 0, 0, 0, 190, 191,
		1, 0, 0, 0, 191, 193, 1, 0, 0, 0, 192, 186, 1, 0, 0, 0, 193, 196, 1, 0,
		0, 0, 194, 192, 1, 0, 0, 0, 194, 195, 1, 0, 0, 0, 195, 48, 1, 0, 0, 0,
		196, 194, 1, 0, 0, 0, 197, 201, 5, 39, 0, 0, 198, 200, 8, 6, 0, 0, 199,
		198, 1, 0, 0, 0, 200, 203, 1, 0, 0, 0, 201, 199, 1, 0, 0, 0, 201, 202,
		1, 0, 0, 0, 202, 204, 1, 0, 0, 0, 203, 201, 1, 0, 0, 0, 204, 205, 5, 39,
		0, 0, 205, 50, 1, 0, 0, 0, 206, 210, 5, 34, 0, 0, 207, 209, 8, 7, 0, 0,
		208, 207, 1, 0, 0, 0, 209, 212, 1, 0, 0, 0, 210, 208, 1, 0, 0, 0, 210,
		211, 1, 0, 0, 0, 211, 213, 1, 0, 0, 0, 212, 210, 1, 0, 0, 0, 213, 214,
		5, 34, 0, 0, 214, 52, 1, 0, 0, 0, 215, 216, 5, 40, 0, 0, 216, 54, 1, 0,
		0, 0, 217, 218, 5, 41, 0, 0, 218, 56, 1, 0, 0, 0, 219, 220, 5, 91, 0, 0,
		220, 58, 1, 0, 0, 0, 221, 222, 5, 93, 0, 0, 222, 60, 1, 0, 0, 0, 223, 224,
		5, 123, 0, 0, 224, 62, 1, 0, 0, 0, 225, 226, 5, 125, 0, 0, 226, 64, 1,
		0, 0, 0, 227, 228, 5, 36, 0, 0, 228, 229, 5, 36, 0, 0, 229, 230, 5, 123,
		0, 0, 230, 66, 1, 0, 0, 0, 231, 232, 5, 36, 0, 0, 232, 233, 5, 123, 0,
		0, 233, 68, 1, 0, 0, 0, 18, 0, 107, 113, 123, 135, 138, 143, 149, 152,
		157, 162, 172, 178, 184, 190, 194, 201, 210, 1, 6, 0, 0,
	}
	deserializer := antlr.NewATNDeserializer(nil)
	staticData.atn = deserializer.Deserialize(staticData.serializedATN)
	atn := staticData.atn
	staticData.decisionToDFA = make([]*antlr.DFA, len(atn.DecisionToState))
	decisionToDFA := staticData.decisionToDFA
	for index, state := range atn.DecisionToState {
		decisionToDFA[index] = antlr.NewDFA(state, index)
	}
}

// EqlLexerInit initializes any static state used to implement EqlLexer. By default the
// static state used to implement the lexer is lazily initialized during the first call to
// NewEqlLexer(). You can call this function if you wish to initialize the static state ahead
// of time.
func EqlLexerInit() {
	staticData := &EqlLexerLexerStaticData
	staticData.once.Do(eqllexerLexerInit)
}

// NewEqlLexer produces a new lexer instance for the optional input antlr.CharStream.
func NewEqlLexer(input antlr.CharStream) *EqlLexer {
	EqlLexerInit()
	l := new(EqlLexer)
	l.BaseLexer = antlr.NewBaseLexer(input)
	staticData := &EqlLexerLexerStaticData
	l.Interpreter = antlr.NewLexerATNSimulator(l, staticData.atn, staticData.decisionToDFA, staticData.PredictionContextCache)
	l.channelNames = staticData.ChannelNames
	l.modeNames = staticData.ModeNames
	l.RuleNames = staticData.RuleNames
	l.LiteralNames = staticData.LiteralNames
	l.SymbolicNames = staticData.SymbolicNames
	l.GrammarFileName = "Eql.g4"
	// TODO: l.EOF = antlr.TokenEOF

	return l
}

// EqlLexer tokens.
const (
	EqlLexerT__0            = 1
	EqlLexerT__1            = 2
	EqlLexerT__2            = 3
	EqlLexerEQ              = 4
	EqlLexerNEQ             = 5
	EqlLexerGT              = 6
	EqlLexerLT              = 7
	EqlLexerGTE             = 8
	EqlLexerLTE             = 9
	EqlLexerADD             = 10
	EqlLexerSUB             = 11
	EqlLexerMUL             = 12
	EqlLexerDIV             = 13
	EqlLexerMOD             = 14
	EqlLexerAND             = 15
	EqlLexerOR              = 16
	EqlLexerTRUE            = 17
	EqlLexerFALSE           = 18
	EqlLexerFLOAT           = 19
	EqlLexerNUMBER          = 20
	EqlLexerWHITESPACE      = 21
	EqlLexerNOT             = 22
	EqlLexerNAME            = 23
	EqlLexerVNAME           = 24
	EqlLexerSTEXT           = 25
	EqlLexerDTEXT           = 26
	EqlLexerLPAR            = 27
	EqlLexerRPAR            = 28
	EqlLexerLARR            = 29
	EqlLexerRARR            = 30
	EqlLexerLDICT           = 31
	EqlLexerRDICT           = 32
	EqlLexerBEGIN_EVARIABLE = 33
	EqlLexerBEGIN_VARIABLE  = 34
)
