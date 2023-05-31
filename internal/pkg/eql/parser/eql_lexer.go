// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Code generated from Eql.g4 by ANTLR 4.12.0. DO NOT EDIT.

package parser

import (
	"fmt"
	"sync"
	"unicode"

	"github.com/antlr/antlr4/runtime/Go/antlr/v4"
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

var eqllexerLexerStaticData struct {
	once                   sync.Once
	serializedATN          []int32
	channelNames           []string
	modeNames              []string
	literalNames           []string
	symbolicNames          []string
	ruleNames              []string
	predictionContextCache *antlr.PredictionContextCache
	atn                    *antlr.ATN
	decisionToDFA          []*antlr.DFA
}

func eqllexerLexerInit() {
	staticData := &eqllexerLexerStaticData
	staticData.channelNames = []string{
		"DEFAULT_TOKEN_CHANNEL", "HIDDEN",
	}
	staticData.modeNames = []string{
		"DEFAULT_MODE",
	}
	staticData.literalNames = []string{
		"", "'|'", "','", "':'", "'=='", "'!='", "'>'", "'<'", "'>='", "'<='",
		"'+'", "'-'", "'*'", "'/'", "'%'", "", "", "", "", "", "", "", "", "",
		"", "", "", "'('", "')'", "'['", "']'", "'{'", "'}'", "'${'",
	}
	staticData.symbolicNames = []string{
		"", "", "", "", "EQ", "NEQ", "GT", "LT", "GTE", "LTE", "ADD", "SUB",
		"MUL", "DIV", "MOD", "AND", "OR", "TRUE", "FALSE", "FLOAT", "NUMBER",
		"WHITESPACE", "NOT", "NAME", "VNAME", "STEXT", "DTEXT", "LPAR", "RPAR",
		"LARR", "RARR", "LDICT", "RDICT", "BEGIN_VARIABLE",
	}
	staticData.ruleNames = []string{
		"T__0", "T__1", "T__2", "EQ", "NEQ", "GT", "LT", "GTE", "LTE", "ADD",
		"SUB", "MUL", "DIV", "MOD", "AND", "OR", "TRUE", "FALSE", "FLOAT", "NUMBER",
		"WHITESPACE", "NOT", "NAME", "VNAME", "STEXT", "DTEXT", "LPAR", "RPAR",
		"LARR", "RARR", "LDICT", "RDICT", "BEGIN_VARIABLE",
	}
	staticData.predictionContextCache = antlr.NewPredictionContextCache()
	staticData.serializedATN = []int32{
		4, 0, 33, 228, 6, -1, 2, 0, 7, 0, 2, 1, 7, 1, 2, 2, 7, 2, 2, 3, 7, 3, 2,
		4, 7, 4, 2, 5, 7, 5, 2, 6, 7, 6, 2, 7, 7, 7, 2, 8, 7, 8, 2, 9, 7, 9, 2,
		10, 7, 10, 2, 11, 7, 11, 2, 12, 7, 12, 2, 13, 7, 13, 2, 14, 7, 14, 2, 15,
		7, 15, 2, 16, 7, 16, 2, 17, 7, 17, 2, 18, 7, 18, 2, 19, 7, 19, 2, 20, 7,
		20, 2, 21, 7, 21, 2, 22, 7, 22, 2, 23, 7, 23, 2, 24, 7, 24, 2, 25, 7, 25,
		2, 26, 7, 26, 2, 27, 7, 27, 2, 28, 7, 28, 2, 29, 7, 29, 2, 30, 7, 30, 2,
		31, 7, 31, 2, 32, 7, 32, 1, 0, 1, 0, 1, 1, 1, 1, 1, 2, 1, 2, 1, 3, 1, 3,
		1, 3, 1, 4, 1, 4, 1, 4, 1, 5, 1, 5, 1, 6, 1, 6, 1, 7, 1, 7, 1, 7, 1, 8,
		1, 8, 1, 8, 1, 9, 1, 9, 1, 10, 1, 10, 1, 11, 1, 11, 1, 12, 1, 12, 1, 13,
		1, 13, 1, 14, 1, 14, 1, 14, 1, 14, 1, 14, 1, 14, 3, 14, 106, 8, 14, 1,
		15, 1, 15, 1, 15, 1, 15, 3, 15, 112, 8, 15, 1, 16, 1, 16, 1, 16, 1, 16,
		1, 16, 1, 16, 1, 16, 1, 16, 3, 16, 122, 8, 16, 1, 17, 1, 17, 1, 17, 1,
		17, 1, 17, 1, 17, 1, 17, 1, 17, 1, 17, 1, 17, 3, 17, 134, 8, 17, 1, 18,
		3, 18, 137, 8, 18, 1, 18, 4, 18, 140, 8, 18, 11, 18, 12, 18, 141, 1, 18,
		1, 18, 4, 18, 146, 8, 18, 11, 18, 12, 18, 147, 1, 19, 3, 19, 151, 8, 19,
		1, 19, 4, 19, 154, 8, 19, 11, 19, 12, 19, 155, 1, 20, 4, 20, 159, 8, 20,
		11, 20, 12, 20, 160, 1, 20, 1, 20, 1, 21, 1, 21, 1, 21, 1, 21, 1, 21, 1,
		21, 3, 21, 171, 8, 21, 1, 22, 1, 22, 5, 22, 175, 8, 22, 10, 22, 12, 22,
		178, 9, 22, 1, 23, 4, 23, 181, 8, 23, 11, 23, 12, 23, 182, 1, 23, 1, 23,
		4, 23, 187, 8, 23, 11, 23, 12, 23, 188, 5, 23, 191, 8, 23, 10, 23, 12,
		23, 194, 9, 23, 1, 24, 1, 24, 5, 24, 198, 8, 24, 10, 24, 12, 24, 201, 9,
		24, 1, 24, 1, 24, 1, 25, 1, 25, 5, 25, 207, 8, 25, 10, 25, 12, 25, 210,
		9, 25, 1, 25, 1, 25, 1, 26, 1, 26, 1, 27, 1, 27, 1, 28, 1, 28, 1, 29, 1,
		29, 1, 30, 1, 30, 1, 31, 1, 31, 1, 32, 1, 32, 1, 32, 0, 0, 33, 1, 1, 3,
		2, 5, 3, 7, 4, 9, 5, 11, 6, 13, 7, 15, 8, 17, 9, 19, 10, 21, 11, 23, 12,
		25, 13, 27, 14, 29, 15, 31, 16, 33, 17, 35, 18, 37, 19, 39, 20, 41, 21,
		43, 22, 45, 23, 47, 24, 49, 25, 51, 26, 53, 27, 55, 28, 57, 29, 59, 30,
		61, 31, 63, 32, 65, 33, 1, 0, 8, 1, 0, 45, 45, 1, 0, 48, 57, 3, 0, 9, 10,
		13, 13, 32, 32, 3, 0, 65, 90, 95, 95, 97, 122, 4, 0, 48, 57, 65, 90, 95,
		95, 97, 122, 5, 0, 45, 45, 47, 57, 65, 90, 95, 95, 97, 122, 3, 0, 10, 10,
		13, 13, 39, 39, 3, 0, 10, 10, 13, 13, 34, 34, 244, 0, 1, 1, 0, 0, 0, 0,
		3, 1, 0, 0, 0, 0, 5, 1, 0, 0, 0, 0, 7, 1, 0, 0, 0, 0, 9, 1, 0, 0, 0, 0,
		11, 1, 0, 0, 0, 0, 13, 1, 0, 0, 0, 0, 15, 1, 0, 0, 0, 0, 17, 1, 0, 0, 0,
		0, 19, 1, 0, 0, 0, 0, 21, 1, 0, 0, 0, 0, 23, 1, 0, 0, 0, 0, 25, 1, 0, 0,
		0, 0, 27, 1, 0, 0, 0, 0, 29, 1, 0, 0, 0, 0, 31, 1, 0, 0, 0, 0, 33, 1, 0,
		0, 0, 0, 35, 1, 0, 0, 0, 0, 37, 1, 0, 0, 0, 0, 39, 1, 0, 0, 0, 0, 41, 1,
		0, 0, 0, 0, 43, 1, 0, 0, 0, 0, 45, 1, 0, 0, 0, 0, 47, 1, 0, 0, 0, 0, 49,
		1, 0, 0, 0, 0, 51, 1, 0, 0, 0, 0, 53, 1, 0, 0, 0, 0, 55, 1, 0, 0, 0, 0,
		57, 1, 0, 0, 0, 0, 59, 1, 0, 0, 0, 0, 61, 1, 0, 0, 0, 0, 63, 1, 0, 0, 0,
		0, 65, 1, 0, 0, 0, 1, 67, 1, 0, 0, 0, 3, 69, 1, 0, 0, 0, 5, 71, 1, 0, 0,
		0, 7, 73, 1, 0, 0, 0, 9, 76, 1, 0, 0, 0, 11, 79, 1, 0, 0, 0, 13, 81, 1,
		0, 0, 0, 15, 83, 1, 0, 0, 0, 17, 86, 1, 0, 0, 0, 19, 89, 1, 0, 0, 0, 21,
		91, 1, 0, 0, 0, 23, 93, 1, 0, 0, 0, 25, 95, 1, 0, 0, 0, 27, 97, 1, 0, 0,
		0, 29, 105, 1, 0, 0, 0, 31, 111, 1, 0, 0, 0, 33, 121, 1, 0, 0, 0, 35, 133,
		1, 0, 0, 0, 37, 136, 1, 0, 0, 0, 39, 150, 1, 0, 0, 0, 41, 158, 1, 0, 0,
		0, 43, 170, 1, 0, 0, 0, 45, 172, 1, 0, 0, 0, 47, 180, 1, 0, 0, 0, 49, 195,
		1, 0, 0, 0, 51, 204, 1, 0, 0, 0, 53, 213, 1, 0, 0, 0, 55, 215, 1, 0, 0,
		0, 57, 217, 1, 0, 0, 0, 59, 219, 1, 0, 0, 0, 61, 221, 1, 0, 0, 0, 63, 223,
		1, 0, 0, 0, 65, 225, 1, 0, 0, 0, 67, 68, 5, 124, 0, 0, 68, 2, 1, 0, 0,
		0, 69, 70, 5, 44, 0, 0, 70, 4, 1, 0, 0, 0, 71, 72, 5, 58, 0, 0, 72, 6,
		1, 0, 0, 0, 73, 74, 5, 61, 0, 0, 74, 75, 5, 61, 0, 0, 75, 8, 1, 0, 0, 0,
		76, 77, 5, 33, 0, 0, 77, 78, 5, 61, 0, 0, 78, 10, 1, 0, 0, 0, 79, 80, 5,
		62, 0, 0, 80, 12, 1, 0, 0, 0, 81, 82, 5, 60, 0, 0, 82, 14, 1, 0, 0, 0,
		83, 84, 5, 62, 0, 0, 84, 85, 5, 61, 0, 0, 85, 16, 1, 0, 0, 0, 86, 87, 5,
		60, 0, 0, 87, 88, 5, 61, 0, 0, 88, 18, 1, 0, 0, 0, 89, 90, 5, 43, 0, 0,
		90, 20, 1, 0, 0, 0, 91, 92, 5, 45, 0, 0, 92, 22, 1, 0, 0, 0, 93, 94, 5,
		42, 0, 0, 94, 24, 1, 0, 0, 0, 95, 96, 5, 47, 0, 0, 96, 26, 1, 0, 0, 0,
		97, 98, 5, 37, 0, 0, 98, 28, 1, 0, 0, 0, 99, 100, 5, 97, 0, 0, 100, 101,
		5, 110, 0, 0, 101, 106, 5, 100, 0, 0, 102, 103, 5, 65, 0, 0, 103, 104,
		5, 78, 0, 0, 104, 106, 5, 68, 0, 0, 105, 99, 1, 0, 0, 0, 105, 102, 1, 0,
		0, 0, 106, 30, 1, 0, 0, 0, 107, 108, 5, 111, 0, 0, 108, 112, 5, 114, 0,
		0, 109, 110, 5, 79, 0, 0, 110, 112, 5, 82, 0, 0, 111, 107, 1, 0, 0, 0,
		111, 109, 1, 0, 0, 0, 112, 32, 1, 0, 0, 0, 113, 114, 5, 116, 0, 0, 114,
		115, 5, 114, 0, 0, 115, 116, 5, 117, 0, 0, 116, 122, 5, 101, 0, 0, 117,
		118, 5, 84, 0, 0, 118, 119, 5, 82, 0, 0, 119, 120, 5, 85, 0, 0, 120, 122,
		5, 69, 0, 0, 121, 113, 1, 0, 0, 0, 121, 117, 1, 0, 0, 0, 122, 34, 1, 0,
		0, 0, 123, 124, 5, 102, 0, 0, 124, 125, 5, 97, 0, 0, 125, 126, 5, 108,
		0, 0, 126, 127, 5, 115, 0, 0, 127, 134, 5, 101, 0, 0, 128, 129, 5, 70,
		0, 0, 129, 130, 5, 65, 0, 0, 130, 131, 5, 76, 0, 0, 131, 132, 5, 83, 0,
		0, 132, 134, 5, 69, 0, 0, 133, 123, 1, 0, 0, 0, 133, 128, 1, 0, 0, 0, 134,
		36, 1, 0, 0, 0, 135, 137, 7, 0, 0, 0, 136, 135, 1, 0, 0, 0, 136, 137, 1,
		0, 0, 0, 137, 139, 1, 0, 0, 0, 138, 140, 7, 1, 0, 0, 139, 138, 1, 0, 0,
		0, 140, 141, 1, 0, 0, 0, 141, 139, 1, 0, 0, 0, 141, 142, 1, 0, 0, 0, 142,
		143, 1, 0, 0, 0, 143, 145, 5, 46, 0, 0, 144, 146, 7, 1, 0, 0, 145, 144,
		1, 0, 0, 0, 146, 147, 1, 0, 0, 0, 147, 145, 1, 0, 0, 0, 147, 148, 1, 0,
		0, 0, 148, 38, 1, 0, 0, 0, 149, 151, 7, 0, 0, 0, 150, 149, 1, 0, 0, 0,
		150, 151, 1, 0, 0, 0, 151, 153, 1, 0, 0, 0, 152, 154, 7, 1, 0, 0, 153,
		152, 1, 0, 0, 0, 154, 155, 1, 0, 0, 0, 155, 153, 1, 0, 0, 0, 155, 156,
		1, 0, 0, 0, 156, 40, 1, 0, 0, 0, 157, 159, 7, 2, 0, 0, 158, 157, 1, 0,
		0, 0, 159, 160, 1, 0, 0, 0, 160, 158, 1, 0, 0, 0, 160, 161, 1, 0, 0, 0,
		161, 162, 1, 0, 0, 0, 162, 163, 6, 20, 0, 0, 163, 42, 1, 0, 0, 0, 164,
		165, 5, 78, 0, 0, 165, 166, 5, 79, 0, 0, 166, 171, 5, 84, 0, 0, 167, 168,
		5, 110, 0, 0, 168, 169, 5, 111, 0, 0, 169, 171, 5, 116, 0, 0, 170, 164,
		1, 0, 0, 0, 170, 167, 1, 0, 0, 0, 171, 44, 1, 0, 0, 0, 172, 176, 7, 3,
		0, 0, 173, 175, 7, 4, 0, 0, 174, 173, 1, 0, 0, 0, 175, 178, 1, 0, 0, 0,
		176, 174, 1, 0, 0, 0, 176, 177, 1, 0, 0, 0, 177, 46, 1, 0, 0, 0, 178, 176,
		1, 0, 0, 0, 179, 181, 7, 5, 0, 0, 180, 179, 1, 0, 0, 0, 181, 182, 1, 0,
		0, 0, 182, 180, 1, 0, 0, 0, 182, 183, 1, 0, 0, 0, 183, 192, 1, 0, 0, 0,
		184, 186, 5, 46, 0, 0, 185, 187, 7, 5, 0, 0, 186, 185, 1, 0, 0, 0, 187,
		188, 1, 0, 0, 0, 188, 186, 1, 0, 0, 0, 188, 189, 1, 0, 0, 0, 189, 191,
		1, 0, 0, 0, 190, 184, 1, 0, 0, 0, 191, 194, 1, 0, 0, 0, 192, 190, 1, 0,
		0, 0, 192, 193, 1, 0, 0, 0, 193, 48, 1, 0, 0, 0, 194, 192, 1, 0, 0, 0,
		195, 199, 5, 39, 0, 0, 196, 198, 8, 6, 0, 0, 197, 196, 1, 0, 0, 0, 198,
		201, 1, 0, 0, 0, 199, 197, 1, 0, 0, 0, 199, 200, 1, 0, 0, 0, 200, 202,
		1, 0, 0, 0, 201, 199, 1, 0, 0, 0, 202, 203, 5, 39, 0, 0, 203, 50, 1, 0,
		0, 0, 204, 208, 5, 34, 0, 0, 205, 207, 8, 7, 0, 0, 206, 205, 1, 0, 0, 0,
		207, 210, 1, 0, 0, 0, 208, 206, 1, 0, 0, 0, 208, 209, 1, 0, 0, 0, 209,
		211, 1, 0, 0, 0, 210, 208, 1, 0, 0, 0, 211, 212, 5, 34, 0, 0, 212, 52,
		1, 0, 0, 0, 213, 214, 5, 40, 0, 0, 214, 54, 1, 0, 0, 0, 215, 216, 5, 41,
		0, 0, 216, 56, 1, 0, 0, 0, 217, 218, 5, 91, 0, 0, 218, 58, 1, 0, 0, 0,
		219, 220, 5, 93, 0, 0, 220, 60, 1, 0, 0, 0, 221, 222, 5, 123, 0, 0, 222,
		62, 1, 0, 0, 0, 223, 224, 5, 125, 0, 0, 224, 64, 1, 0, 0, 0, 225, 226,
		5, 36, 0, 0, 226, 227, 5, 123, 0, 0, 227, 66, 1, 0, 0, 0, 18, 0, 105, 111,
		121, 133, 136, 141, 147, 150, 155, 160, 170, 176, 182, 188, 192, 199, 208,
		1, 6, 0, 0,
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
	staticData := &eqllexerLexerStaticData
	staticData.once.Do(eqllexerLexerInit)
}

// NewEqlLexer produces a new lexer instance for the optional input antlr.CharStream.
func NewEqlLexer(input antlr.CharStream) *EqlLexer {
	EqlLexerInit()
	l := new(EqlLexer)
	l.BaseLexer = antlr.NewBaseLexer(input)
	staticData := &eqllexerLexerStaticData
	l.Interpreter = antlr.NewLexerATNSimulator(l, staticData.atn, staticData.decisionToDFA, staticData.predictionContextCache)
	l.channelNames = staticData.channelNames
	l.modeNames = staticData.modeNames
	l.RuleNames = staticData.ruleNames
	l.LiteralNames = staticData.literalNames
	l.SymbolicNames = staticData.symbolicNames
	l.GrammarFileName = "Eql.g4"
	// TODO: l.EOF = antlr.TokenEOF

	return l
}

// EqlLexer tokens.
const (
	EqlLexerT__0           = 1
	EqlLexerT__1           = 2
	EqlLexerT__2           = 3
	EqlLexerEQ             = 4
	EqlLexerNEQ            = 5
	EqlLexerGT             = 6
	EqlLexerLT             = 7
	EqlLexerGTE            = 8
	EqlLexerLTE            = 9
	EqlLexerADD            = 10
	EqlLexerSUB            = 11
	EqlLexerMUL            = 12
	EqlLexerDIV            = 13
	EqlLexerMOD            = 14
	EqlLexerAND            = 15
	EqlLexerOR             = 16
	EqlLexerTRUE           = 17
	EqlLexerFALSE          = 18
	EqlLexerFLOAT          = 19
	EqlLexerNUMBER         = 20
	EqlLexerWHITESPACE     = 21
	EqlLexerNOT            = 22
	EqlLexerNAME           = 23
	EqlLexerVNAME          = 24
	EqlLexerSTEXT          = 25
	EqlLexerDTEXT          = 26
	EqlLexerLPAR           = 27
	EqlLexerRPAR           = 28
	EqlLexerLARR           = 29
	EqlLexerRARR           = 30
	EqlLexerLDICT          = 31
	EqlLexerRDICT          = 32
	EqlLexerBEGIN_VARIABLE = 33
)
