// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Code generated from Eql.g4 by ANTLR 4.12.0. DO NOT EDIT.

package parser // Eql

import (
	"fmt"
	"strconv"
	"sync"

	"github.com/antlr/antlr4/runtime/Go/antlr/v4"
)

// Suppress unused import errors
var _ = fmt.Printf
var _ = strconv.Itoa
var _ = sync.Once{}

type EqlParser struct {
	*antlr.BaseParser
}

var eqlParserStaticData struct {
	once                   sync.Once
	serializedATN          []int32
	literalNames           []string
	symbolicNames          []string
	ruleNames              []string
	predictionContextCache *antlr.PredictionContextCache
	atn                    *antlr.ATN
	decisionToDFA          []*antlr.DFA
}

func eqlParserInit() {
	staticData := &eqlParserStaticData
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
		"expList", "boolean", "constant", "variable", "variableExp", "exp",
		"arguments", "array", "key", "dict",
	}
	staticData.predictionContextCache = antlr.NewPredictionContextCache()
	staticData.serializedATN = []int32{
		4, 1, 33, 142, 2, 0, 7, 0, 2, 1, 7, 1, 2, 2, 7, 2, 2, 3, 7, 3, 2, 4, 7,
		4, 2, 5, 7, 5, 2, 6, 7, 6, 2, 7, 7, 7, 2, 8, 7, 8, 2, 9, 7, 9, 1, 0, 1,
		0, 1, 0, 1, 1, 1, 1, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 3, 2, 31, 8, 2, 1, 3,
		1, 3, 1, 3, 3, 3, 36, 8, 3, 1, 4, 1, 4, 1, 4, 5, 4, 41, 8, 4, 10, 4, 12,
		4, 44, 9, 4, 1, 5, 1, 5, 1, 5, 1, 5, 1, 5, 1, 5, 1, 5, 1, 5, 1, 5, 1, 5,
		1, 5, 1, 5, 1, 5, 1, 5, 1, 5, 3, 5, 61, 8, 5, 1, 5, 1, 5, 1, 5, 3, 5, 66,
		8, 5, 1, 5, 1, 5, 1, 5, 3, 5, 71, 8, 5, 1, 5, 1, 5, 1, 5, 1, 5, 3, 5, 77,
		8, 5, 1, 5, 1, 5, 1, 5, 1, 5, 1, 5, 1, 5, 1, 5, 1, 5, 1, 5, 1, 5, 1, 5,
		1, 5, 1, 5, 1, 5, 1, 5, 1, 5, 1, 5, 1, 5, 1, 5, 1, 5, 1, 5, 1, 5, 1, 5,
		1, 5, 1, 5, 1, 5, 1, 5, 1, 5, 1, 5, 1, 5, 5, 5, 109, 8, 5, 10, 5, 12, 5,
		112, 9, 5, 1, 6, 1, 6, 1, 6, 5, 6, 117, 8, 6, 10, 6, 12, 6, 120, 9, 6,
		1, 7, 1, 7, 1, 7, 5, 7, 125, 8, 7, 10, 7, 12, 7, 128, 9, 7, 1, 8, 1, 8,
		1, 8, 1, 8, 1, 9, 1, 9, 1, 9, 5, 9, 137, 8, 9, 10, 9, 12, 9, 140, 9, 9,
		1, 9, 0, 1, 10, 10, 0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 0, 5, 1, 0, 17,
		18, 1, 0, 25, 26, 1, 0, 12, 14, 1, 0, 10, 11, 2, 0, 23, 23, 25, 26, 163,
		0, 20, 1, 0, 0, 0, 2, 23, 1, 0, 0, 0, 4, 30, 1, 0, 0, 0, 6, 35, 1, 0, 0,
		0, 8, 37, 1, 0, 0, 0, 10, 76, 1, 0, 0, 0, 12, 113, 1, 0, 0, 0, 14, 121,
		1, 0, 0, 0, 16, 129, 1, 0, 0, 0, 18, 133, 1, 0, 0, 0, 20, 21, 3, 10, 5,
		0, 21, 22, 5, 0, 0, 1, 22, 1, 1, 0, 0, 0, 23, 24, 7, 0, 0, 0, 24, 3, 1,
		0, 0, 0, 25, 31, 5, 25, 0, 0, 26, 31, 5, 26, 0, 0, 27, 31, 5, 19, 0, 0,
		28, 31, 5, 20, 0, 0, 29, 31, 3, 2, 1, 0, 30, 25, 1, 0, 0, 0, 30, 26, 1,
		0, 0, 0, 30, 27, 1, 0, 0, 0, 30, 28, 1, 0, 0, 0, 30, 29, 1, 0, 0, 0, 31,
		5, 1, 0, 0, 0, 32, 36, 5, 23, 0, 0, 33, 36, 5, 24, 0, 0, 34, 36, 3, 4,
		2, 0, 35, 32, 1, 0, 0, 0, 35, 33, 1, 0, 0, 0, 35, 34, 1, 0, 0, 0, 36, 7,
		1, 0, 0, 0, 37, 42, 3, 6, 3, 0, 38, 39, 5, 1, 0, 0, 39, 41, 3, 6, 3, 0,
		40, 38, 1, 0, 0, 0, 41, 44, 1, 0, 0, 0, 42, 40, 1, 0, 0, 0, 42, 43, 1,
		0, 0, 0, 43, 9, 1, 0, 0, 0, 44, 42, 1, 0, 0, 0, 45, 46, 6, 5, -1, 0, 46,
		47, 5, 27, 0, 0, 47, 48, 3, 10, 5, 0, 48, 49, 5, 28, 0, 0, 49, 77, 1, 0,
		0, 0, 50, 51, 5, 22, 0, 0, 51, 77, 3, 10, 5, 17, 52, 77, 3, 2, 1, 0, 53,
		54, 5, 33, 0, 0, 54, 55, 3, 8, 4, 0, 55, 56, 5, 32, 0, 0, 56, 77, 1, 0,
		0, 0, 57, 58, 5, 23, 0, 0, 58, 60, 5, 27, 0, 0, 59, 61, 3, 12, 6, 0, 60,
		59, 1, 0, 0, 0, 60, 61, 1, 0, 0, 0, 61, 62, 1, 0, 0, 0, 62, 77, 5, 28,
		0, 0, 63, 65, 5, 29, 0, 0, 64, 66, 3, 14, 7, 0, 65, 64, 1, 0, 0, 0, 65,
		66, 1, 0, 0, 0, 66, 67, 1, 0, 0, 0, 67, 77, 5, 30, 0, 0, 68, 70, 5, 31,
		0, 0, 69, 71, 3, 18, 9, 0, 70, 69, 1, 0, 0, 0, 70, 71, 1, 0, 0, 0, 71,
		72, 1, 0, 0, 0, 72, 77, 5, 32, 0, 0, 73, 77, 7, 1, 0, 0, 74, 77, 5, 19,
		0, 0, 75, 77, 5, 20, 0, 0, 76, 45, 1, 0, 0, 0, 76, 50, 1, 0, 0, 0, 76,
		52, 1, 0, 0, 0, 76, 53, 1, 0, 0, 0, 76, 57, 1, 0, 0, 0, 76, 63, 1, 0, 0,
		0, 76, 68, 1, 0, 0, 0, 76, 73, 1, 0, 0, 0, 76, 74, 1, 0, 0, 0, 76, 75,
		1, 0, 0, 0, 77, 110, 1, 0, 0, 0, 78, 79, 10, 19, 0, 0, 79, 80, 7, 2, 0,
		0, 80, 109, 3, 10, 5, 20, 81, 82, 10, 18, 0, 0, 82, 83, 7, 3, 0, 0, 83,
		109, 3, 10, 5, 19, 84, 85, 10, 16, 0, 0, 85, 86, 5, 4, 0, 0, 86, 109, 3,
		10, 5, 17, 87, 88, 10, 15, 0, 0, 88, 89, 5, 5, 0, 0, 89, 109, 3, 10, 5,
		16, 90, 91, 10, 14, 0, 0, 91, 92, 5, 9, 0, 0, 92, 109, 3, 10, 5, 15, 93,
		94, 10, 13, 0, 0, 94, 95, 5, 8, 0, 0, 95, 109, 3, 10, 5, 14, 96, 97, 10,
		12, 0, 0, 97, 98, 5, 7, 0, 0, 98, 109, 3, 10, 5, 13, 99, 100, 10, 11, 0,
		0, 100, 101, 5, 6, 0, 0, 101, 109, 3, 10, 5, 12, 102, 103, 10, 10, 0, 0,
		103, 104, 5, 15, 0, 0, 104, 109, 3, 10, 5, 11, 105, 106, 10, 9, 0, 0, 106,
		107, 5, 16, 0, 0, 107, 109, 3, 10, 5, 10, 108, 78, 1, 0, 0, 0, 108, 81,
		1, 0, 0, 0, 108, 84, 1, 0, 0, 0, 108, 87, 1, 0, 0, 0, 108, 90, 1, 0, 0,
		0, 108, 93, 1, 0, 0, 0, 108, 96, 1, 0, 0, 0, 108, 99, 1, 0, 0, 0, 108,
		102, 1, 0, 0, 0, 108, 105, 1, 0, 0, 0, 109, 112, 1, 0, 0, 0, 110, 108,
		1, 0, 0, 0, 110, 111, 1, 0, 0, 0, 111, 11, 1, 0, 0, 0, 112, 110, 1, 0,
		0, 0, 113, 118, 3, 10, 5, 0, 114, 115, 5, 2, 0, 0, 115, 117, 3, 10, 5,
		0, 116, 114, 1, 0, 0, 0, 117, 120, 1, 0, 0, 0, 118, 116, 1, 0, 0, 0, 118,
		119, 1, 0, 0, 0, 119, 13, 1, 0, 0, 0, 120, 118, 1, 0, 0, 0, 121, 126, 3,
		4, 2, 0, 122, 123, 5, 2, 0, 0, 123, 125, 3, 4, 2, 0, 124, 122, 1, 0, 0,
		0, 125, 128, 1, 0, 0, 0, 126, 124, 1, 0, 0, 0, 126, 127, 1, 0, 0, 0, 127,
		15, 1, 0, 0, 0, 128, 126, 1, 0, 0, 0, 129, 130, 7, 4, 0, 0, 130, 131, 5,
		3, 0, 0, 131, 132, 3, 4, 2, 0, 132, 17, 1, 0, 0, 0, 133, 138, 3, 16, 8,
		0, 134, 135, 5, 2, 0, 0, 135, 137, 3, 16, 8, 0, 136, 134, 1, 0, 0, 0, 137,
		140, 1, 0, 0, 0, 138, 136, 1, 0, 0, 0, 138, 139, 1, 0, 0, 0, 139, 19, 1,
		0, 0, 0, 140, 138, 1, 0, 0, 0, 12, 30, 35, 42, 60, 65, 70, 76, 108, 110,
		118, 126, 138,
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

// EqlParserInit initializes any static state used to implement EqlParser. By default the
// static state used to implement the parser is lazily initialized during the first call to
// NewEqlParser(). You can call this function if you wish to initialize the static state ahead
// of time.
func EqlParserInit() {
	staticData := &eqlParserStaticData
	staticData.once.Do(eqlParserInit)
}

// NewEqlParser produces a new parser instance for the optional input antlr.TokenStream.
func NewEqlParser(input antlr.TokenStream) *EqlParser {
	EqlParserInit()
	this := new(EqlParser)
	this.BaseParser = antlr.NewBaseParser(input)
	staticData := &eqlParserStaticData
	this.Interpreter = antlr.NewParserATNSimulator(this, staticData.atn, staticData.decisionToDFA, staticData.predictionContextCache)
	this.RuleNames = staticData.ruleNames
	this.LiteralNames = staticData.literalNames
	this.SymbolicNames = staticData.symbolicNames
	this.GrammarFileName = "Eql.g4"

	return this
}

// EqlParser tokens.
const (
	EqlParserEOF            = antlr.TokenEOF
	EqlParserT__0           = 1
	EqlParserT__1           = 2
	EqlParserT__2           = 3
	EqlParserEQ             = 4
	EqlParserNEQ            = 5
	EqlParserGT             = 6
	EqlParserLT             = 7
	EqlParserGTE            = 8
	EqlParserLTE            = 9
	EqlParserADD            = 10
	EqlParserSUB            = 11
	EqlParserMUL            = 12
	EqlParserDIV            = 13
	EqlParserMOD            = 14
	EqlParserAND            = 15
	EqlParserOR             = 16
	EqlParserTRUE           = 17
	EqlParserFALSE          = 18
	EqlParserFLOAT          = 19
	EqlParserNUMBER         = 20
	EqlParserWHITESPACE     = 21
	EqlParserNOT            = 22
	EqlParserNAME           = 23
	EqlParserVNAME          = 24
	EqlParserSTEXT          = 25
	EqlParserDTEXT          = 26
	EqlParserLPAR           = 27
	EqlParserRPAR           = 28
	EqlParserLARR           = 29
	EqlParserRARR           = 30
	EqlParserLDICT          = 31
	EqlParserRDICT          = 32
	EqlParserBEGIN_VARIABLE = 33
)

// EqlParser rules.
const (
	EqlParserRULE_expList     = 0
	EqlParserRULE_boolean     = 1
	EqlParserRULE_constant    = 2
	EqlParserRULE_variable    = 3
	EqlParserRULE_variableExp = 4
	EqlParserRULE_exp         = 5
	EqlParserRULE_arguments   = 6
	EqlParserRULE_array       = 7
	EqlParserRULE_key         = 8
	EqlParserRULE_dict        = 9
)

// IExpListContext is an interface to support dynamic dispatch.
type IExpListContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// Getter signatures
	Exp() IExpContext
	EOF() antlr.TerminalNode

	// IsExpListContext differentiates from other interfaces.
	IsExpListContext()
}

type ExpListContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyExpListContext() *ExpListContext {
	var p = new(ExpListContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = EqlParserRULE_expList
	return p
}

func (*ExpListContext) IsExpListContext() {}

func NewExpListContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *ExpListContext {
	var p = new(ExpListContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = EqlParserRULE_expList

	return p
}

func (s *ExpListContext) GetParser() antlr.Parser { return s.parser }

func (s *ExpListContext) Exp() IExpContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IExpContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(IExpContext)
}

func (s *ExpListContext) EOF() antlr.TerminalNode {
	return s.GetToken(EqlParserEOF, 0)
}

func (s *ExpListContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ExpListContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *ExpListContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.EnterExpList(s)
	}
}

func (s *ExpListContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.ExitExpList(s)
	}
}

func (s *ExpListContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case EqlVisitor:
		return t.VisitExpList(s)

	default:
		return t.VisitChildren(s)
	}
}

func (p *EqlParser) ExpList() (localctx IExpListContext) {
	this := p
	_ = this

	localctx = NewExpListContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 0, EqlParserRULE_expList)

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(20)
		p.exp(0)
	}
	{
		p.SetState(21)
		p.Match(EqlParserEOF)
	}

	return localctx
}

// IBooleanContext is an interface to support dynamic dispatch.
type IBooleanContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// Getter signatures
	TRUE() antlr.TerminalNode
	FALSE() antlr.TerminalNode

	// IsBooleanContext differentiates from other interfaces.
	IsBooleanContext()
}

type BooleanContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyBooleanContext() *BooleanContext {
	var p = new(BooleanContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = EqlParserRULE_boolean
	return p
}

func (*BooleanContext) IsBooleanContext() {}

func NewBooleanContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *BooleanContext {
	var p = new(BooleanContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = EqlParserRULE_boolean

	return p
}

func (s *BooleanContext) GetParser() antlr.Parser { return s.parser }

func (s *BooleanContext) TRUE() antlr.TerminalNode {
	return s.GetToken(EqlParserTRUE, 0)
}

func (s *BooleanContext) FALSE() antlr.TerminalNode {
	return s.GetToken(EqlParserFALSE, 0)
}

func (s *BooleanContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *BooleanContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *BooleanContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.EnterBoolean(s)
	}
}

func (s *BooleanContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.ExitBoolean(s)
	}
}

func (s *BooleanContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case EqlVisitor:
		return t.VisitBoolean(s)

	default:
		return t.VisitChildren(s)
	}
}

func (p *EqlParser) Boolean() (localctx IBooleanContext) {
	this := p
	_ = this

	localctx = NewBooleanContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 2, EqlParserRULE_boolean)
	var _la int

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(23)
		_la = p.GetTokenStream().LA(1)

		if !(_la == EqlParserTRUE || _la == EqlParserFALSE) {
			p.GetErrorHandler().RecoverInline(p)
		} else {
			p.GetErrorHandler().ReportMatch(p)
			p.Consume()
		}
	}

	return localctx
}

// IConstantContext is an interface to support dynamic dispatch.
type IConstantContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// Getter signatures
	STEXT() antlr.TerminalNode
	DTEXT() antlr.TerminalNode
	FLOAT() antlr.TerminalNode
	NUMBER() antlr.TerminalNode
	Boolean() IBooleanContext

	// IsConstantContext differentiates from other interfaces.
	IsConstantContext()
}

type ConstantContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyConstantContext() *ConstantContext {
	var p = new(ConstantContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = EqlParserRULE_constant
	return p
}

func (*ConstantContext) IsConstantContext() {}

func NewConstantContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *ConstantContext {
	var p = new(ConstantContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = EqlParserRULE_constant

	return p
}

func (s *ConstantContext) GetParser() antlr.Parser { return s.parser }

func (s *ConstantContext) STEXT() antlr.TerminalNode {
	return s.GetToken(EqlParserSTEXT, 0)
}

func (s *ConstantContext) DTEXT() antlr.TerminalNode {
	return s.GetToken(EqlParserDTEXT, 0)
}

func (s *ConstantContext) FLOAT() antlr.TerminalNode {
	return s.GetToken(EqlParserFLOAT, 0)
}

func (s *ConstantContext) NUMBER() antlr.TerminalNode {
	return s.GetToken(EqlParserNUMBER, 0)
}

func (s *ConstantContext) Boolean() IBooleanContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IBooleanContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(IBooleanContext)
}

func (s *ConstantContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ConstantContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *ConstantContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.EnterConstant(s)
	}
}

func (s *ConstantContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.ExitConstant(s)
	}
}

func (s *ConstantContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case EqlVisitor:
		return t.VisitConstant(s)

	default:
		return t.VisitChildren(s)
	}
}

func (p *EqlParser) Constant() (localctx IConstantContext) {
	this := p
	_ = this

	localctx = NewConstantContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 4, EqlParserRULE_constant)

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.SetState(30)
	p.GetErrorHandler().Sync(p)

	switch p.GetTokenStream().LA(1) {
	case EqlParserSTEXT:
		p.EnterOuterAlt(localctx, 1)
		{
			p.SetState(25)
			p.Match(EqlParserSTEXT)
		}

	case EqlParserDTEXT:
		p.EnterOuterAlt(localctx, 2)
		{
			p.SetState(26)
			p.Match(EqlParserDTEXT)
		}

	case EqlParserFLOAT:
		p.EnterOuterAlt(localctx, 3)
		{
			p.SetState(27)
			p.Match(EqlParserFLOAT)
		}

	case EqlParserNUMBER:
		p.EnterOuterAlt(localctx, 4)
		{
			p.SetState(28)
			p.Match(EqlParserNUMBER)
		}

	case EqlParserTRUE, EqlParserFALSE:
		p.EnterOuterAlt(localctx, 5)
		{
			p.SetState(29)
			p.Boolean()
		}

	default:
		panic(antlr.NewNoViableAltException(p, nil, nil, nil, nil, nil))
	}

	return localctx
}

// IVariableContext is an interface to support dynamic dispatch.
type IVariableContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// Getter signatures
	NAME() antlr.TerminalNode
	VNAME() antlr.TerminalNode
	Constant() IConstantContext

	// IsVariableContext differentiates from other interfaces.
	IsVariableContext()
}

type VariableContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyVariableContext() *VariableContext {
	var p = new(VariableContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = EqlParserRULE_variable
	return p
}

func (*VariableContext) IsVariableContext() {}

func NewVariableContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *VariableContext {
	var p = new(VariableContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = EqlParserRULE_variable

	return p
}

func (s *VariableContext) GetParser() antlr.Parser { return s.parser }

func (s *VariableContext) NAME() antlr.TerminalNode {
	return s.GetToken(EqlParserNAME, 0)
}

func (s *VariableContext) VNAME() antlr.TerminalNode {
	return s.GetToken(EqlParserVNAME, 0)
}

func (s *VariableContext) Constant() IConstantContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IConstantContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(IConstantContext)
}

func (s *VariableContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *VariableContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *VariableContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.EnterVariable(s)
	}
}

func (s *VariableContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.ExitVariable(s)
	}
}

func (s *VariableContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case EqlVisitor:
		return t.VisitVariable(s)

	default:
		return t.VisitChildren(s)
	}
}

func (p *EqlParser) Variable() (localctx IVariableContext) {
	this := p
	_ = this

	localctx = NewVariableContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 6, EqlParserRULE_variable)

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.SetState(35)
	p.GetErrorHandler().Sync(p)

	switch p.GetTokenStream().LA(1) {
	case EqlParserNAME:
		p.EnterOuterAlt(localctx, 1)
		{
			p.SetState(32)
			p.Match(EqlParserNAME)
		}

	case EqlParserVNAME:
		p.EnterOuterAlt(localctx, 2)
		{
			p.SetState(33)
			p.Match(EqlParserVNAME)
		}

	case EqlParserTRUE, EqlParserFALSE, EqlParserFLOAT, EqlParserNUMBER, EqlParserSTEXT, EqlParserDTEXT:
		p.EnterOuterAlt(localctx, 3)
		{
			p.SetState(34)
			p.Constant()
		}

	default:
		panic(antlr.NewNoViableAltException(p, nil, nil, nil, nil, nil))
	}

	return localctx
}

// IVariableExpContext is an interface to support dynamic dispatch.
type IVariableExpContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// Getter signatures
	AllVariable() []IVariableContext
	Variable(i int) IVariableContext

	// IsVariableExpContext differentiates from other interfaces.
	IsVariableExpContext()
}

type VariableExpContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyVariableExpContext() *VariableExpContext {
	var p = new(VariableExpContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = EqlParserRULE_variableExp
	return p
}

func (*VariableExpContext) IsVariableExpContext() {}

func NewVariableExpContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *VariableExpContext {
	var p = new(VariableExpContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = EqlParserRULE_variableExp

	return p
}

func (s *VariableExpContext) GetParser() antlr.Parser { return s.parser }

func (s *VariableExpContext) AllVariable() []IVariableContext {
	children := s.GetChildren()
	len := 0
	for _, ctx := range children {
		if _, ok := ctx.(IVariableContext); ok {
			len++
		}
	}

	tst := make([]IVariableContext, len)
	i := 0
	for _, ctx := range children {
		if t, ok := ctx.(IVariableContext); ok {
			tst[i] = t.(IVariableContext)
			i++
		}
	}

	return tst
}

func (s *VariableExpContext) Variable(i int) IVariableContext {
	var t antlr.RuleContext
	j := 0
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IVariableContext); ok {
			if j == i {
				t = ctx.(antlr.RuleContext)
				break
			}
			j++
		}
	}

	if t == nil {
		return nil
	}

	return t.(IVariableContext)
}

func (s *VariableExpContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *VariableExpContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *VariableExpContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.EnterVariableExp(s)
	}
}

func (s *VariableExpContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.ExitVariableExp(s)
	}
}

func (s *VariableExpContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case EqlVisitor:
		return t.VisitVariableExp(s)

	default:
		return t.VisitChildren(s)
	}
}

func (p *EqlParser) VariableExp() (localctx IVariableExpContext) {
	this := p
	_ = this

	localctx = NewVariableExpContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 8, EqlParserRULE_variableExp)
	var _la int

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(37)
		p.Variable()
	}
	p.SetState(42)
	p.GetErrorHandler().Sync(p)
	_la = p.GetTokenStream().LA(1)

	for _la == EqlParserT__0 {
		{
			p.SetState(38)
			p.Match(EqlParserT__0)
		}
		{
			p.SetState(39)
			p.Variable()
		}

		p.SetState(44)
		p.GetErrorHandler().Sync(p)
		_la = p.GetTokenStream().LA(1)
	}

	return localctx
}

// IExpContext is an interface to support dynamic dispatch.
type IExpContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser
	// IsExpContext differentiates from other interfaces.
	IsExpContext()
}

type ExpContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyExpContext() *ExpContext {
	var p = new(ExpContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = EqlParserRULE_exp
	return p
}

func (*ExpContext) IsExpContext() {}

func NewExpContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *ExpContext {
	var p = new(ExpContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = EqlParserRULE_exp

	return p
}

func (s *ExpContext) GetParser() antlr.Parser { return s.parser }

func (s *ExpContext) CopyFrom(ctx *ExpContext) {
	s.BaseParserRuleContext.CopyFrom(ctx.BaseParserRuleContext)
}

func (s *ExpContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ExpContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

type ExpArithmeticNEQContext struct {
	*ExpContext
	left  IExpContext
	right IExpContext
}

func NewExpArithmeticNEQContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *ExpArithmeticNEQContext {
	var p = new(ExpArithmeticNEQContext)

	p.ExpContext = NewEmptyExpContext()
	p.parser = parser
	p.CopyFrom(ctx.(*ExpContext))

	return p
}

func (s *ExpArithmeticNEQContext) GetLeft() IExpContext { return s.left }

func (s *ExpArithmeticNEQContext) GetRight() IExpContext { return s.right }

func (s *ExpArithmeticNEQContext) SetLeft(v IExpContext) { s.left = v }

func (s *ExpArithmeticNEQContext) SetRight(v IExpContext) { s.right = v }

func (s *ExpArithmeticNEQContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ExpArithmeticNEQContext) NEQ() antlr.TerminalNode {
	return s.GetToken(EqlParserNEQ, 0)
}

func (s *ExpArithmeticNEQContext) AllExp() []IExpContext {
	children := s.GetChildren()
	len := 0
	for _, ctx := range children {
		if _, ok := ctx.(IExpContext); ok {
			len++
		}
	}

	tst := make([]IExpContext, len)
	i := 0
	for _, ctx := range children {
		if t, ok := ctx.(IExpContext); ok {
			tst[i] = t.(IExpContext)
			i++
		}
	}

	return tst
}

func (s *ExpArithmeticNEQContext) Exp(i int) IExpContext {
	var t antlr.RuleContext
	j := 0
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IExpContext); ok {
			if j == i {
				t = ctx.(antlr.RuleContext)
				break
			}
			j++
		}
	}

	if t == nil {
		return nil
	}

	return t.(IExpContext)
}

func (s *ExpArithmeticNEQContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.EnterExpArithmeticNEQ(s)
	}
}

func (s *ExpArithmeticNEQContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.ExitExpArithmeticNEQ(s)
	}
}

func (s *ExpArithmeticNEQContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case EqlVisitor:
		return t.VisitExpArithmeticNEQ(s)

	default:
		return t.VisitChildren(s)
	}
}

type ExpArithmeticEQContext struct {
	*ExpContext
	left  IExpContext
	right IExpContext
}

func NewExpArithmeticEQContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *ExpArithmeticEQContext {
	var p = new(ExpArithmeticEQContext)

	p.ExpContext = NewEmptyExpContext()
	p.parser = parser
	p.CopyFrom(ctx.(*ExpContext))

	return p
}

func (s *ExpArithmeticEQContext) GetLeft() IExpContext { return s.left }

func (s *ExpArithmeticEQContext) GetRight() IExpContext { return s.right }

func (s *ExpArithmeticEQContext) SetLeft(v IExpContext) { s.left = v }

func (s *ExpArithmeticEQContext) SetRight(v IExpContext) { s.right = v }

func (s *ExpArithmeticEQContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ExpArithmeticEQContext) EQ() antlr.TerminalNode {
	return s.GetToken(EqlParserEQ, 0)
}

func (s *ExpArithmeticEQContext) AllExp() []IExpContext {
	children := s.GetChildren()
	len := 0
	for _, ctx := range children {
		if _, ok := ctx.(IExpContext); ok {
			len++
		}
	}

	tst := make([]IExpContext, len)
	i := 0
	for _, ctx := range children {
		if t, ok := ctx.(IExpContext); ok {
			tst[i] = t.(IExpContext)
			i++
		}
	}

	return tst
}

func (s *ExpArithmeticEQContext) Exp(i int) IExpContext {
	var t antlr.RuleContext
	j := 0
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IExpContext); ok {
			if j == i {
				t = ctx.(antlr.RuleContext)
				break
			}
			j++
		}
	}

	if t == nil {
		return nil
	}

	return t.(IExpContext)
}

func (s *ExpArithmeticEQContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.EnterExpArithmeticEQ(s)
	}
}

func (s *ExpArithmeticEQContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.ExitExpArithmeticEQ(s)
	}
}

func (s *ExpArithmeticEQContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case EqlVisitor:
		return t.VisitExpArithmeticEQ(s)

	default:
		return t.VisitChildren(s)
	}
}

type ExpArithmeticGTEContext struct {
	*ExpContext
	left  IExpContext
	right IExpContext
}

func NewExpArithmeticGTEContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *ExpArithmeticGTEContext {
	var p = new(ExpArithmeticGTEContext)

	p.ExpContext = NewEmptyExpContext()
	p.parser = parser
	p.CopyFrom(ctx.(*ExpContext))

	return p
}

func (s *ExpArithmeticGTEContext) GetLeft() IExpContext { return s.left }

func (s *ExpArithmeticGTEContext) GetRight() IExpContext { return s.right }

func (s *ExpArithmeticGTEContext) SetLeft(v IExpContext) { s.left = v }

func (s *ExpArithmeticGTEContext) SetRight(v IExpContext) { s.right = v }

func (s *ExpArithmeticGTEContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ExpArithmeticGTEContext) GTE() antlr.TerminalNode {
	return s.GetToken(EqlParserGTE, 0)
}

func (s *ExpArithmeticGTEContext) AllExp() []IExpContext {
	children := s.GetChildren()
	len := 0
	for _, ctx := range children {
		if _, ok := ctx.(IExpContext); ok {
			len++
		}
	}

	tst := make([]IExpContext, len)
	i := 0
	for _, ctx := range children {
		if t, ok := ctx.(IExpContext); ok {
			tst[i] = t.(IExpContext)
			i++
		}
	}

	return tst
}

func (s *ExpArithmeticGTEContext) Exp(i int) IExpContext {
	var t antlr.RuleContext
	j := 0
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IExpContext); ok {
			if j == i {
				t = ctx.(antlr.RuleContext)
				break
			}
			j++
		}
	}

	if t == nil {
		return nil
	}

	return t.(IExpContext)
}

func (s *ExpArithmeticGTEContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.EnterExpArithmeticGTE(s)
	}
}

func (s *ExpArithmeticGTEContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.ExitExpArithmeticGTE(s)
	}
}

func (s *ExpArithmeticGTEContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case EqlVisitor:
		return t.VisitExpArithmeticGTE(s)

	default:
		return t.VisitChildren(s)
	}
}

type ExpArithmeticLTEContext struct {
	*ExpContext
	left  IExpContext
	right IExpContext
}

func NewExpArithmeticLTEContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *ExpArithmeticLTEContext {
	var p = new(ExpArithmeticLTEContext)

	p.ExpContext = NewEmptyExpContext()
	p.parser = parser
	p.CopyFrom(ctx.(*ExpContext))

	return p
}

func (s *ExpArithmeticLTEContext) GetLeft() IExpContext { return s.left }

func (s *ExpArithmeticLTEContext) GetRight() IExpContext { return s.right }

func (s *ExpArithmeticLTEContext) SetLeft(v IExpContext) { s.left = v }

func (s *ExpArithmeticLTEContext) SetRight(v IExpContext) { s.right = v }

func (s *ExpArithmeticLTEContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ExpArithmeticLTEContext) LTE() antlr.TerminalNode {
	return s.GetToken(EqlParserLTE, 0)
}

func (s *ExpArithmeticLTEContext) AllExp() []IExpContext {
	children := s.GetChildren()
	len := 0
	for _, ctx := range children {
		if _, ok := ctx.(IExpContext); ok {
			len++
		}
	}

	tst := make([]IExpContext, len)
	i := 0
	for _, ctx := range children {
		if t, ok := ctx.(IExpContext); ok {
			tst[i] = t.(IExpContext)
			i++
		}
	}

	return tst
}

func (s *ExpArithmeticLTEContext) Exp(i int) IExpContext {
	var t antlr.RuleContext
	j := 0
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IExpContext); ok {
			if j == i {
				t = ctx.(antlr.RuleContext)
				break
			}
			j++
		}
	}

	if t == nil {
		return nil
	}

	return t.(IExpContext)
}

func (s *ExpArithmeticLTEContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.EnterExpArithmeticLTE(s)
	}
}

func (s *ExpArithmeticLTEContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.ExitExpArithmeticLTE(s)
	}
}

func (s *ExpArithmeticLTEContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case EqlVisitor:
		return t.VisitExpArithmeticLTE(s)

	default:
		return t.VisitChildren(s)
	}
}

type ExpArithmeticGTContext struct {
	*ExpContext
	left  IExpContext
	right IExpContext
}

func NewExpArithmeticGTContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *ExpArithmeticGTContext {
	var p = new(ExpArithmeticGTContext)

	p.ExpContext = NewEmptyExpContext()
	p.parser = parser
	p.CopyFrom(ctx.(*ExpContext))

	return p
}

func (s *ExpArithmeticGTContext) GetLeft() IExpContext { return s.left }

func (s *ExpArithmeticGTContext) GetRight() IExpContext { return s.right }

func (s *ExpArithmeticGTContext) SetLeft(v IExpContext) { s.left = v }

func (s *ExpArithmeticGTContext) SetRight(v IExpContext) { s.right = v }

func (s *ExpArithmeticGTContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ExpArithmeticGTContext) GT() antlr.TerminalNode {
	return s.GetToken(EqlParserGT, 0)
}

func (s *ExpArithmeticGTContext) AllExp() []IExpContext {
	children := s.GetChildren()
	len := 0
	for _, ctx := range children {
		if _, ok := ctx.(IExpContext); ok {
			len++
		}
	}

	tst := make([]IExpContext, len)
	i := 0
	for _, ctx := range children {
		if t, ok := ctx.(IExpContext); ok {
			tst[i] = t.(IExpContext)
			i++
		}
	}

	return tst
}

func (s *ExpArithmeticGTContext) Exp(i int) IExpContext {
	var t antlr.RuleContext
	j := 0
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IExpContext); ok {
			if j == i {
				t = ctx.(antlr.RuleContext)
				break
			}
			j++
		}
	}

	if t == nil {
		return nil
	}

	return t.(IExpContext)
}

func (s *ExpArithmeticGTContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.EnterExpArithmeticGT(s)
	}
}

func (s *ExpArithmeticGTContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.ExitExpArithmeticGT(s)
	}
}

func (s *ExpArithmeticGTContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case EqlVisitor:
		return t.VisitExpArithmeticGT(s)

	default:
		return t.VisitChildren(s)
	}
}

type ExpArithmeticMulDivModContext struct {
	*ExpContext
	left  IExpContext
	right IExpContext
}

func NewExpArithmeticMulDivModContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *ExpArithmeticMulDivModContext {
	var p = new(ExpArithmeticMulDivModContext)

	p.ExpContext = NewEmptyExpContext()
	p.parser = parser
	p.CopyFrom(ctx.(*ExpContext))

	return p
}

func (s *ExpArithmeticMulDivModContext) GetLeft() IExpContext { return s.left }

func (s *ExpArithmeticMulDivModContext) GetRight() IExpContext { return s.right }

func (s *ExpArithmeticMulDivModContext) SetLeft(v IExpContext) { s.left = v }

func (s *ExpArithmeticMulDivModContext) SetRight(v IExpContext) { s.right = v }

func (s *ExpArithmeticMulDivModContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ExpArithmeticMulDivModContext) AllExp() []IExpContext {
	children := s.GetChildren()
	len := 0
	for _, ctx := range children {
		if _, ok := ctx.(IExpContext); ok {
			len++
		}
	}

	tst := make([]IExpContext, len)
	i := 0
	for _, ctx := range children {
		if t, ok := ctx.(IExpContext); ok {
			tst[i] = t.(IExpContext)
			i++
		}
	}

	return tst
}

func (s *ExpArithmeticMulDivModContext) Exp(i int) IExpContext {
	var t antlr.RuleContext
	j := 0
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IExpContext); ok {
			if j == i {
				t = ctx.(antlr.RuleContext)
				break
			}
			j++
		}
	}

	if t == nil {
		return nil
	}

	return t.(IExpContext)
}

func (s *ExpArithmeticMulDivModContext) MUL() antlr.TerminalNode {
	return s.GetToken(EqlParserMUL, 0)
}

func (s *ExpArithmeticMulDivModContext) DIV() antlr.TerminalNode {
	return s.GetToken(EqlParserDIV, 0)
}

func (s *ExpArithmeticMulDivModContext) MOD() antlr.TerminalNode {
	return s.GetToken(EqlParserMOD, 0)
}

func (s *ExpArithmeticMulDivModContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.EnterExpArithmeticMulDivMod(s)
	}
}

func (s *ExpArithmeticMulDivModContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.ExitExpArithmeticMulDivMod(s)
	}
}

func (s *ExpArithmeticMulDivModContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case EqlVisitor:
		return t.VisitExpArithmeticMulDivMod(s)

	default:
		return t.VisitChildren(s)
	}
}

type ExpDictContext struct {
	*ExpContext
}

func NewExpDictContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *ExpDictContext {
	var p = new(ExpDictContext)

	p.ExpContext = NewEmptyExpContext()
	p.parser = parser
	p.CopyFrom(ctx.(*ExpContext))

	return p
}

func (s *ExpDictContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ExpDictContext) LDICT() antlr.TerminalNode {
	return s.GetToken(EqlParserLDICT, 0)
}

func (s *ExpDictContext) RDICT() antlr.TerminalNode {
	return s.GetToken(EqlParserRDICT, 0)
}

func (s *ExpDictContext) Dict() IDictContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IDictContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(IDictContext)
}

func (s *ExpDictContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.EnterExpDict(s)
	}
}

func (s *ExpDictContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.ExitExpDict(s)
	}
}

func (s *ExpDictContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case EqlVisitor:
		return t.VisitExpDict(s)

	default:
		return t.VisitChildren(s)
	}
}

type ExpTextContext struct {
	*ExpContext
}

func NewExpTextContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *ExpTextContext {
	var p = new(ExpTextContext)

	p.ExpContext = NewEmptyExpContext()
	p.parser = parser
	p.CopyFrom(ctx.(*ExpContext))

	return p
}

func (s *ExpTextContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ExpTextContext) STEXT() antlr.TerminalNode {
	return s.GetToken(EqlParserSTEXT, 0)
}

func (s *ExpTextContext) DTEXT() antlr.TerminalNode {
	return s.GetToken(EqlParserDTEXT, 0)
}

func (s *ExpTextContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.EnterExpText(s)
	}
}

func (s *ExpTextContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.ExitExpText(s)
	}
}

func (s *ExpTextContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case EqlVisitor:
		return t.VisitExpText(s)

	default:
		return t.VisitChildren(s)
	}
}

type ExpNumberContext struct {
	*ExpContext
}

func NewExpNumberContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *ExpNumberContext {
	var p = new(ExpNumberContext)

	p.ExpContext = NewEmptyExpContext()
	p.parser = parser
	p.CopyFrom(ctx.(*ExpContext))

	return p
}

func (s *ExpNumberContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ExpNumberContext) NUMBER() antlr.TerminalNode {
	return s.GetToken(EqlParserNUMBER, 0)
}

func (s *ExpNumberContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.EnterExpNumber(s)
	}
}

func (s *ExpNumberContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.ExitExpNumber(s)
	}
}

func (s *ExpNumberContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case EqlVisitor:
		return t.VisitExpNumber(s)

	default:
		return t.VisitChildren(s)
	}
}

type ExpLogicalAndContext struct {
	*ExpContext
	left  IExpContext
	right IExpContext
}

func NewExpLogicalAndContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *ExpLogicalAndContext {
	var p = new(ExpLogicalAndContext)

	p.ExpContext = NewEmptyExpContext()
	p.parser = parser
	p.CopyFrom(ctx.(*ExpContext))

	return p
}

func (s *ExpLogicalAndContext) GetLeft() IExpContext { return s.left }

func (s *ExpLogicalAndContext) GetRight() IExpContext { return s.right }

func (s *ExpLogicalAndContext) SetLeft(v IExpContext) { s.left = v }

func (s *ExpLogicalAndContext) SetRight(v IExpContext) { s.right = v }

func (s *ExpLogicalAndContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ExpLogicalAndContext) AND() antlr.TerminalNode {
	return s.GetToken(EqlParserAND, 0)
}

func (s *ExpLogicalAndContext) AllExp() []IExpContext {
	children := s.GetChildren()
	len := 0
	for _, ctx := range children {
		if _, ok := ctx.(IExpContext); ok {
			len++
		}
	}

	tst := make([]IExpContext, len)
	i := 0
	for _, ctx := range children {
		if t, ok := ctx.(IExpContext); ok {
			tst[i] = t.(IExpContext)
			i++
		}
	}

	return tst
}

func (s *ExpLogicalAndContext) Exp(i int) IExpContext {
	var t antlr.RuleContext
	j := 0
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IExpContext); ok {
			if j == i {
				t = ctx.(antlr.RuleContext)
				break
			}
			j++
		}
	}

	if t == nil {
		return nil
	}

	return t.(IExpContext)
}

func (s *ExpLogicalAndContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.EnterExpLogicalAnd(s)
	}
}

func (s *ExpLogicalAndContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.ExitExpLogicalAnd(s)
	}
}

func (s *ExpLogicalAndContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case EqlVisitor:
		return t.VisitExpLogicalAnd(s)

	default:
		return t.VisitChildren(s)
	}
}

type ExpLogicalORContext struct {
	*ExpContext
	left  IExpContext
	right IExpContext
}

func NewExpLogicalORContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *ExpLogicalORContext {
	var p = new(ExpLogicalORContext)

	p.ExpContext = NewEmptyExpContext()
	p.parser = parser
	p.CopyFrom(ctx.(*ExpContext))

	return p
}

func (s *ExpLogicalORContext) GetLeft() IExpContext { return s.left }

func (s *ExpLogicalORContext) GetRight() IExpContext { return s.right }

func (s *ExpLogicalORContext) SetLeft(v IExpContext) { s.left = v }

func (s *ExpLogicalORContext) SetRight(v IExpContext) { s.right = v }

func (s *ExpLogicalORContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ExpLogicalORContext) OR() antlr.TerminalNode {
	return s.GetToken(EqlParserOR, 0)
}

func (s *ExpLogicalORContext) AllExp() []IExpContext {
	children := s.GetChildren()
	len := 0
	for _, ctx := range children {
		if _, ok := ctx.(IExpContext); ok {
			len++
		}
	}

	tst := make([]IExpContext, len)
	i := 0
	for _, ctx := range children {
		if t, ok := ctx.(IExpContext); ok {
			tst[i] = t.(IExpContext)
			i++
		}
	}

	return tst
}

func (s *ExpLogicalORContext) Exp(i int) IExpContext {
	var t antlr.RuleContext
	j := 0
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IExpContext); ok {
			if j == i {
				t = ctx.(antlr.RuleContext)
				break
			}
			j++
		}
	}

	if t == nil {
		return nil
	}

	return t.(IExpContext)
}

func (s *ExpLogicalORContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.EnterExpLogicalOR(s)
	}
}

func (s *ExpLogicalORContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.ExitExpLogicalOR(s)
	}
}

func (s *ExpLogicalORContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case EqlVisitor:
		return t.VisitExpLogicalOR(s)

	default:
		return t.VisitChildren(s)
	}
}

type ExpFloatContext struct {
	*ExpContext
}

func NewExpFloatContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *ExpFloatContext {
	var p = new(ExpFloatContext)

	p.ExpContext = NewEmptyExpContext()
	p.parser = parser
	p.CopyFrom(ctx.(*ExpContext))

	return p
}

func (s *ExpFloatContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ExpFloatContext) FLOAT() antlr.TerminalNode {
	return s.GetToken(EqlParserFLOAT, 0)
}

func (s *ExpFloatContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.EnterExpFloat(s)
	}
}

func (s *ExpFloatContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.ExitExpFloat(s)
	}
}

func (s *ExpFloatContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case EqlVisitor:
		return t.VisitExpFloat(s)

	default:
		return t.VisitChildren(s)
	}
}

type ExpVariableContext struct {
	*ExpContext
}

func NewExpVariableContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *ExpVariableContext {
	var p = new(ExpVariableContext)

	p.ExpContext = NewEmptyExpContext()
	p.parser = parser
	p.CopyFrom(ctx.(*ExpContext))

	return p
}

func (s *ExpVariableContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ExpVariableContext) BEGIN_VARIABLE() antlr.TerminalNode {
	return s.GetToken(EqlParserBEGIN_VARIABLE, 0)
}

func (s *ExpVariableContext) VariableExp() IVariableExpContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IVariableExpContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(IVariableExpContext)
}

func (s *ExpVariableContext) RDICT() antlr.TerminalNode {
	return s.GetToken(EqlParserRDICT, 0)
}

func (s *ExpVariableContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.EnterExpVariable(s)
	}
}

func (s *ExpVariableContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.ExitExpVariable(s)
	}
}

func (s *ExpVariableContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case EqlVisitor:
		return t.VisitExpVariable(s)

	default:
		return t.VisitChildren(s)
	}
}

type ExpArrayContext struct {
	*ExpContext
}

func NewExpArrayContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *ExpArrayContext {
	var p = new(ExpArrayContext)

	p.ExpContext = NewEmptyExpContext()
	p.parser = parser
	p.CopyFrom(ctx.(*ExpContext))

	return p
}

func (s *ExpArrayContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ExpArrayContext) LARR() antlr.TerminalNode {
	return s.GetToken(EqlParserLARR, 0)
}

func (s *ExpArrayContext) RARR() antlr.TerminalNode {
	return s.GetToken(EqlParserRARR, 0)
}

func (s *ExpArrayContext) Array() IArrayContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IArrayContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(IArrayContext)
}

func (s *ExpArrayContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.EnterExpArray(s)
	}
}

func (s *ExpArrayContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.ExitExpArray(s)
	}
}

func (s *ExpArrayContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case EqlVisitor:
		return t.VisitExpArray(s)

	default:
		return t.VisitChildren(s)
	}
}

type ExpNotContext struct {
	*ExpContext
}

func NewExpNotContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *ExpNotContext {
	var p = new(ExpNotContext)

	p.ExpContext = NewEmptyExpContext()
	p.parser = parser
	p.CopyFrom(ctx.(*ExpContext))

	return p
}

func (s *ExpNotContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ExpNotContext) NOT() antlr.TerminalNode {
	return s.GetToken(EqlParserNOT, 0)
}

func (s *ExpNotContext) Exp() IExpContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IExpContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(IExpContext)
}

func (s *ExpNotContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.EnterExpNot(s)
	}
}

func (s *ExpNotContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.ExitExpNot(s)
	}
}

func (s *ExpNotContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case EqlVisitor:
		return t.VisitExpNot(s)

	default:
		return t.VisitChildren(s)
	}
}

type ExpInParenContext struct {
	*ExpContext
}

func NewExpInParenContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *ExpInParenContext {
	var p = new(ExpInParenContext)

	p.ExpContext = NewEmptyExpContext()
	p.parser = parser
	p.CopyFrom(ctx.(*ExpContext))

	return p
}

func (s *ExpInParenContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ExpInParenContext) LPAR() antlr.TerminalNode {
	return s.GetToken(EqlParserLPAR, 0)
}

func (s *ExpInParenContext) Exp() IExpContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IExpContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(IExpContext)
}

func (s *ExpInParenContext) RPAR() antlr.TerminalNode {
	return s.GetToken(EqlParserRPAR, 0)
}

func (s *ExpInParenContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.EnterExpInParen(s)
	}
}

func (s *ExpInParenContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.ExitExpInParen(s)
	}
}

func (s *ExpInParenContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case EqlVisitor:
		return t.VisitExpInParen(s)

	default:
		return t.VisitChildren(s)
	}
}

type ExpBooleanContext struct {
	*ExpContext
}

func NewExpBooleanContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *ExpBooleanContext {
	var p = new(ExpBooleanContext)

	p.ExpContext = NewEmptyExpContext()
	p.parser = parser
	p.CopyFrom(ctx.(*ExpContext))

	return p
}

func (s *ExpBooleanContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ExpBooleanContext) Boolean() IBooleanContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IBooleanContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(IBooleanContext)
}

func (s *ExpBooleanContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.EnterExpBoolean(s)
	}
}

func (s *ExpBooleanContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.ExitExpBoolean(s)
	}
}

func (s *ExpBooleanContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case EqlVisitor:
		return t.VisitExpBoolean(s)

	default:
		return t.VisitChildren(s)
	}
}

type ExpArithmeticAddSubContext struct {
	*ExpContext
	left  IExpContext
	right IExpContext
}

func NewExpArithmeticAddSubContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *ExpArithmeticAddSubContext {
	var p = new(ExpArithmeticAddSubContext)

	p.ExpContext = NewEmptyExpContext()
	p.parser = parser
	p.CopyFrom(ctx.(*ExpContext))

	return p
}

func (s *ExpArithmeticAddSubContext) GetLeft() IExpContext { return s.left }

func (s *ExpArithmeticAddSubContext) GetRight() IExpContext { return s.right }

func (s *ExpArithmeticAddSubContext) SetLeft(v IExpContext) { s.left = v }

func (s *ExpArithmeticAddSubContext) SetRight(v IExpContext) { s.right = v }

func (s *ExpArithmeticAddSubContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ExpArithmeticAddSubContext) AllExp() []IExpContext {
	children := s.GetChildren()
	len := 0
	for _, ctx := range children {
		if _, ok := ctx.(IExpContext); ok {
			len++
		}
	}

	tst := make([]IExpContext, len)
	i := 0
	for _, ctx := range children {
		if t, ok := ctx.(IExpContext); ok {
			tst[i] = t.(IExpContext)
			i++
		}
	}

	return tst
}

func (s *ExpArithmeticAddSubContext) Exp(i int) IExpContext {
	var t antlr.RuleContext
	j := 0
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IExpContext); ok {
			if j == i {
				t = ctx.(antlr.RuleContext)
				break
			}
			j++
		}
	}

	if t == nil {
		return nil
	}

	return t.(IExpContext)
}

func (s *ExpArithmeticAddSubContext) ADD() antlr.TerminalNode {
	return s.GetToken(EqlParserADD, 0)
}

func (s *ExpArithmeticAddSubContext) SUB() antlr.TerminalNode {
	return s.GetToken(EqlParserSUB, 0)
}

func (s *ExpArithmeticAddSubContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.EnterExpArithmeticAddSub(s)
	}
}

func (s *ExpArithmeticAddSubContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.ExitExpArithmeticAddSub(s)
	}
}

func (s *ExpArithmeticAddSubContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case EqlVisitor:
		return t.VisitExpArithmeticAddSub(s)

	default:
		return t.VisitChildren(s)
	}
}

type ExpFunctionContext struct {
	*ExpContext
}

func NewExpFunctionContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *ExpFunctionContext {
	var p = new(ExpFunctionContext)

	p.ExpContext = NewEmptyExpContext()
	p.parser = parser
	p.CopyFrom(ctx.(*ExpContext))

	return p
}

func (s *ExpFunctionContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ExpFunctionContext) NAME() antlr.TerminalNode {
	return s.GetToken(EqlParserNAME, 0)
}

func (s *ExpFunctionContext) LPAR() antlr.TerminalNode {
	return s.GetToken(EqlParserLPAR, 0)
}

func (s *ExpFunctionContext) RPAR() antlr.TerminalNode {
	return s.GetToken(EqlParserRPAR, 0)
}

func (s *ExpFunctionContext) Arguments() IArgumentsContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IArgumentsContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(IArgumentsContext)
}

func (s *ExpFunctionContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.EnterExpFunction(s)
	}
}

func (s *ExpFunctionContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.ExitExpFunction(s)
	}
}

func (s *ExpFunctionContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case EqlVisitor:
		return t.VisitExpFunction(s)

	default:
		return t.VisitChildren(s)
	}
}

type ExpArithmeticLTContext struct {
	*ExpContext
	left  IExpContext
	right IExpContext
}

func NewExpArithmeticLTContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *ExpArithmeticLTContext {
	var p = new(ExpArithmeticLTContext)

	p.ExpContext = NewEmptyExpContext()
	p.parser = parser
	p.CopyFrom(ctx.(*ExpContext))

	return p
}

func (s *ExpArithmeticLTContext) GetLeft() IExpContext { return s.left }

func (s *ExpArithmeticLTContext) GetRight() IExpContext { return s.right }

func (s *ExpArithmeticLTContext) SetLeft(v IExpContext) { s.left = v }

func (s *ExpArithmeticLTContext) SetRight(v IExpContext) { s.right = v }

func (s *ExpArithmeticLTContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ExpArithmeticLTContext) LT() antlr.TerminalNode {
	return s.GetToken(EqlParserLT, 0)
}

func (s *ExpArithmeticLTContext) AllExp() []IExpContext {
	children := s.GetChildren()
	len := 0
	for _, ctx := range children {
		if _, ok := ctx.(IExpContext); ok {
			len++
		}
	}

	tst := make([]IExpContext, len)
	i := 0
	for _, ctx := range children {
		if t, ok := ctx.(IExpContext); ok {
			tst[i] = t.(IExpContext)
			i++
		}
	}

	return tst
}

func (s *ExpArithmeticLTContext) Exp(i int) IExpContext {
	var t antlr.RuleContext
	j := 0
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IExpContext); ok {
			if j == i {
				t = ctx.(antlr.RuleContext)
				break
			}
			j++
		}
	}

	if t == nil {
		return nil
	}

	return t.(IExpContext)
}

func (s *ExpArithmeticLTContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.EnterExpArithmeticLT(s)
	}
}

func (s *ExpArithmeticLTContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.ExitExpArithmeticLT(s)
	}
}

func (s *ExpArithmeticLTContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case EqlVisitor:
		return t.VisitExpArithmeticLT(s)

	default:
		return t.VisitChildren(s)
	}
}

func (p *EqlParser) Exp() (localctx IExpContext) {
	return p.exp(0)
}

func (p *EqlParser) exp(_p int) (localctx IExpContext) {
	this := p
	_ = this

	var _parentctx antlr.ParserRuleContext = p.GetParserRuleContext()
	_parentState := p.GetState()
	localctx = NewExpContext(p, p.GetParserRuleContext(), _parentState)
	var _prevctx IExpContext = localctx
	var _ antlr.ParserRuleContext = _prevctx // TODO: To prevent unused variable warning.
	_startState := 10
	p.EnterRecursionRule(localctx, 10, EqlParserRULE_exp, _p)
	var _la int

	defer func() {
		p.UnrollRecursionContexts(_parentctx)
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	var _alt int

	p.EnterOuterAlt(localctx, 1)
	p.SetState(76)
	p.GetErrorHandler().Sync(p)

	switch p.GetTokenStream().LA(1) {
	case EqlParserLPAR:
		localctx = NewExpInParenContext(p, localctx)
		p.SetParserRuleContext(localctx)
		_prevctx = localctx

		{
			p.SetState(46)
			p.Match(EqlParserLPAR)
		}
		{
			p.SetState(47)
			p.exp(0)
		}
		{
			p.SetState(48)
			p.Match(EqlParserRPAR)
		}

	case EqlParserNOT:
		localctx = NewExpNotContext(p, localctx)
		p.SetParserRuleContext(localctx)
		_prevctx = localctx
		{
			p.SetState(50)
			p.Match(EqlParserNOT)
		}
		{
			p.SetState(51)
			p.exp(17)
		}

	case EqlParserTRUE, EqlParserFALSE:
		localctx = NewExpBooleanContext(p, localctx)
		p.SetParserRuleContext(localctx)
		_prevctx = localctx
		{
			p.SetState(52)
			p.Boolean()
		}

	case EqlParserBEGIN_VARIABLE:
		localctx = NewExpVariableContext(p, localctx)
		p.SetParserRuleContext(localctx)
		_prevctx = localctx
		{
			p.SetState(53)
			p.Match(EqlParserBEGIN_VARIABLE)
		}
		{
			p.SetState(54)
			p.VariableExp()
		}
		{
			p.SetState(55)
			p.Match(EqlParserRDICT)
		}

	case EqlParserNAME:
		localctx = NewExpFunctionContext(p, localctx)
		p.SetParserRuleContext(localctx)
		_prevctx = localctx
		{
			p.SetState(57)
			p.Match(EqlParserNAME)
		}
		{
			p.SetState(58)
			p.Match(EqlParserLPAR)
		}
		p.SetState(60)
		p.GetErrorHandler().Sync(p)
		_la = p.GetTokenStream().LA(1)

		if (int64(_la) & ^0x3f) == 0 && ((int64(1)<<_la)&11523719168) != 0 {
			{
				p.SetState(59)
				p.Arguments()
			}

		}
		{
			p.SetState(62)
			p.Match(EqlParserRPAR)
		}

	case EqlParserLARR:
		localctx = NewExpArrayContext(p, localctx)
		p.SetParserRuleContext(localctx)
		_prevctx = localctx
		{
			p.SetState(63)
			p.Match(EqlParserLARR)
		}
		p.SetState(65)
		p.GetErrorHandler().Sync(p)
		_la = p.GetTokenStream().LA(1)

		if (int64(_la) & ^0x3f) == 0 && ((int64(1)<<_la)&102629376) != 0 {
			{
				p.SetState(64)
				p.Array()
			}

		}
		{
			p.SetState(67)
			p.Match(EqlParserRARR)
		}

	case EqlParserLDICT:
		localctx = NewExpDictContext(p, localctx)
		p.SetParserRuleContext(localctx)
		_prevctx = localctx
		{
			p.SetState(68)
			p.Match(EqlParserLDICT)
		}
		p.SetState(70)
		p.GetErrorHandler().Sync(p)
		_la = p.GetTokenStream().LA(1)

		if (int64(_la) & ^0x3f) == 0 && ((int64(1)<<_la)&109051904) != 0 {
			{
				p.SetState(69)
				p.Dict()
			}

		}
		{
			p.SetState(72)
			p.Match(EqlParserRDICT)
		}

	case EqlParserSTEXT, EqlParserDTEXT:
		localctx = NewExpTextContext(p, localctx)
		p.SetParserRuleContext(localctx)
		_prevctx = localctx
		{
			p.SetState(73)
			_la = p.GetTokenStream().LA(1)

			if !(_la == EqlParserSTEXT || _la == EqlParserDTEXT) {
				p.GetErrorHandler().RecoverInline(p)
			} else {
				p.GetErrorHandler().ReportMatch(p)
				p.Consume()
			}
		}

	case EqlParserFLOAT:
		localctx = NewExpFloatContext(p, localctx)
		p.SetParserRuleContext(localctx)
		_prevctx = localctx
		{
			p.SetState(74)
			p.Match(EqlParserFLOAT)
		}

	case EqlParserNUMBER:
		localctx = NewExpNumberContext(p, localctx)
		p.SetParserRuleContext(localctx)
		_prevctx = localctx
		{
			p.SetState(75)
			p.Match(EqlParserNUMBER)
		}

	default:
		panic(antlr.NewNoViableAltException(p, nil, nil, nil, nil, nil))
	}
	p.GetParserRuleContext().SetStop(p.GetTokenStream().LT(-1))
	p.SetState(110)
	p.GetErrorHandler().Sync(p)
	_alt = p.GetInterpreter().AdaptivePredict(p.GetTokenStream(), 8, p.GetParserRuleContext())

	for _alt != 2 && _alt != antlr.ATNInvalidAltNumber {
		if _alt == 1 {
			if p.GetParseListeners() != nil {
				p.TriggerExitRuleEvent()
			}
			_prevctx = localctx
			p.SetState(108)
			p.GetErrorHandler().Sync(p)
			switch p.GetInterpreter().AdaptivePredict(p.GetTokenStream(), 7, p.GetParserRuleContext()) {
			case 1:
				localctx = NewExpArithmeticMulDivModContext(p, NewExpContext(p, _parentctx, _parentState))
				localctx.(*ExpArithmeticMulDivModContext).left = _prevctx

				p.PushNewRecursionContext(localctx, _startState, EqlParserRULE_exp)
				p.SetState(78)

				if !(p.Precpred(p.GetParserRuleContext(), 19)) {
					panic(antlr.NewFailedPredicateException(p, "p.Precpred(p.GetParserRuleContext(), 19)", ""))
				}
				{
					p.SetState(79)
					_la = p.GetTokenStream().LA(1)

					if !((int64(_la) & ^0x3f) == 0 && ((int64(1)<<_la)&28672) != 0) {
						p.GetErrorHandler().RecoverInline(p)
					} else {
						p.GetErrorHandler().ReportMatch(p)
						p.Consume()
					}
				}
				{
					p.SetState(80)

					var _x = p.exp(20)

					localctx.(*ExpArithmeticMulDivModContext).right = _x
				}

			case 2:
				localctx = NewExpArithmeticAddSubContext(p, NewExpContext(p, _parentctx, _parentState))
				localctx.(*ExpArithmeticAddSubContext).left = _prevctx

				p.PushNewRecursionContext(localctx, _startState, EqlParserRULE_exp)
				p.SetState(81)

				if !(p.Precpred(p.GetParserRuleContext(), 18)) {
					panic(antlr.NewFailedPredicateException(p, "p.Precpred(p.GetParserRuleContext(), 18)", ""))
				}
				{
					p.SetState(82)
					_la = p.GetTokenStream().LA(1)

					if !(_la == EqlParserADD || _la == EqlParserSUB) {
						p.GetErrorHandler().RecoverInline(p)
					} else {
						p.GetErrorHandler().ReportMatch(p)
						p.Consume()
					}
				}
				{
					p.SetState(83)

					var _x = p.exp(19)

					localctx.(*ExpArithmeticAddSubContext).right = _x
				}

			case 3:
				localctx = NewExpArithmeticEQContext(p, NewExpContext(p, _parentctx, _parentState))
				localctx.(*ExpArithmeticEQContext).left = _prevctx

				p.PushNewRecursionContext(localctx, _startState, EqlParserRULE_exp)
				p.SetState(84)

				if !(p.Precpred(p.GetParserRuleContext(), 16)) {
					panic(antlr.NewFailedPredicateException(p, "p.Precpred(p.GetParserRuleContext(), 16)", ""))
				}
				{
					p.SetState(85)
					p.Match(EqlParserEQ)
				}
				{
					p.SetState(86)

					var _x = p.exp(17)

					localctx.(*ExpArithmeticEQContext).right = _x
				}

			case 4:
				localctx = NewExpArithmeticNEQContext(p, NewExpContext(p, _parentctx, _parentState))
				localctx.(*ExpArithmeticNEQContext).left = _prevctx

				p.PushNewRecursionContext(localctx, _startState, EqlParserRULE_exp)
				p.SetState(87)

				if !(p.Precpred(p.GetParserRuleContext(), 15)) {
					panic(antlr.NewFailedPredicateException(p, "p.Precpred(p.GetParserRuleContext(), 15)", ""))
				}
				{
					p.SetState(88)
					p.Match(EqlParserNEQ)
				}
				{
					p.SetState(89)

					var _x = p.exp(16)

					localctx.(*ExpArithmeticNEQContext).right = _x
				}

			case 5:
				localctx = NewExpArithmeticLTEContext(p, NewExpContext(p, _parentctx, _parentState))
				localctx.(*ExpArithmeticLTEContext).left = _prevctx

				p.PushNewRecursionContext(localctx, _startState, EqlParserRULE_exp)
				p.SetState(90)

				if !(p.Precpred(p.GetParserRuleContext(), 14)) {
					panic(antlr.NewFailedPredicateException(p, "p.Precpred(p.GetParserRuleContext(), 14)", ""))
				}
				{
					p.SetState(91)
					p.Match(EqlParserLTE)
				}
				{
					p.SetState(92)

					var _x = p.exp(15)

					localctx.(*ExpArithmeticLTEContext).right = _x
				}

			case 6:
				localctx = NewExpArithmeticGTEContext(p, NewExpContext(p, _parentctx, _parentState))
				localctx.(*ExpArithmeticGTEContext).left = _prevctx

				p.PushNewRecursionContext(localctx, _startState, EqlParserRULE_exp)
				p.SetState(93)

				if !(p.Precpred(p.GetParserRuleContext(), 13)) {
					panic(antlr.NewFailedPredicateException(p, "p.Precpred(p.GetParserRuleContext(), 13)", ""))
				}
				{
					p.SetState(94)
					p.Match(EqlParserGTE)
				}
				{
					p.SetState(95)

					var _x = p.exp(14)

					localctx.(*ExpArithmeticGTEContext).right = _x
				}

			case 7:
				localctx = NewExpArithmeticLTContext(p, NewExpContext(p, _parentctx, _parentState))
				localctx.(*ExpArithmeticLTContext).left = _prevctx

				p.PushNewRecursionContext(localctx, _startState, EqlParserRULE_exp)
				p.SetState(96)

				if !(p.Precpred(p.GetParserRuleContext(), 12)) {
					panic(antlr.NewFailedPredicateException(p, "p.Precpred(p.GetParserRuleContext(), 12)", ""))
				}
				{
					p.SetState(97)
					p.Match(EqlParserLT)
				}
				{
					p.SetState(98)

					var _x = p.exp(13)

					localctx.(*ExpArithmeticLTContext).right = _x
				}

			case 8:
				localctx = NewExpArithmeticGTContext(p, NewExpContext(p, _parentctx, _parentState))
				localctx.(*ExpArithmeticGTContext).left = _prevctx

				p.PushNewRecursionContext(localctx, _startState, EqlParserRULE_exp)
				p.SetState(99)

				if !(p.Precpred(p.GetParserRuleContext(), 11)) {
					panic(antlr.NewFailedPredicateException(p, "p.Precpred(p.GetParserRuleContext(), 11)", ""))
				}
				{
					p.SetState(100)
					p.Match(EqlParserGT)
				}
				{
					p.SetState(101)

					var _x = p.exp(12)

					localctx.(*ExpArithmeticGTContext).right = _x
				}

			case 9:
				localctx = NewExpLogicalAndContext(p, NewExpContext(p, _parentctx, _parentState))
				localctx.(*ExpLogicalAndContext).left = _prevctx

				p.PushNewRecursionContext(localctx, _startState, EqlParserRULE_exp)
				p.SetState(102)

				if !(p.Precpred(p.GetParserRuleContext(), 10)) {
					panic(antlr.NewFailedPredicateException(p, "p.Precpred(p.GetParserRuleContext(), 10)", ""))
				}
				{
					p.SetState(103)
					p.Match(EqlParserAND)
				}
				{
					p.SetState(104)

					var _x = p.exp(11)

					localctx.(*ExpLogicalAndContext).right = _x
				}

			case 10:
				localctx = NewExpLogicalORContext(p, NewExpContext(p, _parentctx, _parentState))
				localctx.(*ExpLogicalORContext).left = _prevctx

				p.PushNewRecursionContext(localctx, _startState, EqlParserRULE_exp)
				p.SetState(105)

				if !(p.Precpred(p.GetParserRuleContext(), 9)) {
					panic(antlr.NewFailedPredicateException(p, "p.Precpred(p.GetParserRuleContext(), 9)", ""))
				}
				{
					p.SetState(106)
					p.Match(EqlParserOR)
				}
				{
					p.SetState(107)

					var _x = p.exp(10)

					localctx.(*ExpLogicalORContext).right = _x
				}

			}

		}
		p.SetState(112)
		p.GetErrorHandler().Sync(p)
		_alt = p.GetInterpreter().AdaptivePredict(p.GetTokenStream(), 8, p.GetParserRuleContext())
	}

	return localctx
}

// IArgumentsContext is an interface to support dynamic dispatch.
type IArgumentsContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// Getter signatures
	AllExp() []IExpContext
	Exp(i int) IExpContext

	// IsArgumentsContext differentiates from other interfaces.
	IsArgumentsContext()
}

type ArgumentsContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyArgumentsContext() *ArgumentsContext {
	var p = new(ArgumentsContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = EqlParserRULE_arguments
	return p
}

func (*ArgumentsContext) IsArgumentsContext() {}

func NewArgumentsContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *ArgumentsContext {
	var p = new(ArgumentsContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = EqlParserRULE_arguments

	return p
}

func (s *ArgumentsContext) GetParser() antlr.Parser { return s.parser }

func (s *ArgumentsContext) AllExp() []IExpContext {
	children := s.GetChildren()
	len := 0
	for _, ctx := range children {
		if _, ok := ctx.(IExpContext); ok {
			len++
		}
	}

	tst := make([]IExpContext, len)
	i := 0
	for _, ctx := range children {
		if t, ok := ctx.(IExpContext); ok {
			tst[i] = t.(IExpContext)
			i++
		}
	}

	return tst
}

func (s *ArgumentsContext) Exp(i int) IExpContext {
	var t antlr.RuleContext
	j := 0
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IExpContext); ok {
			if j == i {
				t = ctx.(antlr.RuleContext)
				break
			}
			j++
		}
	}

	if t == nil {
		return nil
	}

	return t.(IExpContext)
}

func (s *ArgumentsContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ArgumentsContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *ArgumentsContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.EnterArguments(s)
	}
}

func (s *ArgumentsContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.ExitArguments(s)
	}
}

func (s *ArgumentsContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case EqlVisitor:
		return t.VisitArguments(s)

	default:
		return t.VisitChildren(s)
	}
}

func (p *EqlParser) Arguments() (localctx IArgumentsContext) {
	this := p
	_ = this

	localctx = NewArgumentsContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 12, EqlParserRULE_arguments)
	var _la int

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(113)
		p.exp(0)
	}
	p.SetState(118)
	p.GetErrorHandler().Sync(p)
	_la = p.GetTokenStream().LA(1)

	for _la == EqlParserT__1 {
		{
			p.SetState(114)
			p.Match(EqlParserT__1)
		}
		{
			p.SetState(115)
			p.exp(0)
		}

		p.SetState(120)
		p.GetErrorHandler().Sync(p)
		_la = p.GetTokenStream().LA(1)
	}

	return localctx
}

// IArrayContext is an interface to support dynamic dispatch.
type IArrayContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// Getter signatures
	AllConstant() []IConstantContext
	Constant(i int) IConstantContext

	// IsArrayContext differentiates from other interfaces.
	IsArrayContext()
}

type ArrayContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyArrayContext() *ArrayContext {
	var p = new(ArrayContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = EqlParserRULE_array
	return p
}

func (*ArrayContext) IsArrayContext() {}

func NewArrayContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *ArrayContext {
	var p = new(ArrayContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = EqlParserRULE_array

	return p
}

func (s *ArrayContext) GetParser() antlr.Parser { return s.parser }

func (s *ArrayContext) AllConstant() []IConstantContext {
	children := s.GetChildren()
	len := 0
	for _, ctx := range children {
		if _, ok := ctx.(IConstantContext); ok {
			len++
		}
	}

	tst := make([]IConstantContext, len)
	i := 0
	for _, ctx := range children {
		if t, ok := ctx.(IConstantContext); ok {
			tst[i] = t.(IConstantContext)
			i++
		}
	}

	return tst
}

func (s *ArrayContext) Constant(i int) IConstantContext {
	var t antlr.RuleContext
	j := 0
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IConstantContext); ok {
			if j == i {
				t = ctx.(antlr.RuleContext)
				break
			}
			j++
		}
	}

	if t == nil {
		return nil
	}

	return t.(IConstantContext)
}

func (s *ArrayContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ArrayContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *ArrayContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.EnterArray(s)
	}
}

func (s *ArrayContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.ExitArray(s)
	}
}

func (s *ArrayContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case EqlVisitor:
		return t.VisitArray(s)

	default:
		return t.VisitChildren(s)
	}
}

func (p *EqlParser) Array() (localctx IArrayContext) {
	this := p
	_ = this

	localctx = NewArrayContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 14, EqlParserRULE_array)
	var _la int

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(121)
		p.Constant()
	}
	p.SetState(126)
	p.GetErrorHandler().Sync(p)
	_la = p.GetTokenStream().LA(1)

	for _la == EqlParserT__1 {
		{
			p.SetState(122)
			p.Match(EqlParserT__1)
		}
		{
			p.SetState(123)
			p.Constant()
		}

		p.SetState(128)
		p.GetErrorHandler().Sync(p)
		_la = p.GetTokenStream().LA(1)
	}

	return localctx
}

// IKeyContext is an interface to support dynamic dispatch.
type IKeyContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// Getter signatures
	Constant() IConstantContext
	NAME() antlr.TerminalNode
	STEXT() antlr.TerminalNode
	DTEXT() antlr.TerminalNode

	// IsKeyContext differentiates from other interfaces.
	IsKeyContext()
}

type KeyContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyKeyContext() *KeyContext {
	var p = new(KeyContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = EqlParserRULE_key
	return p
}

func (*KeyContext) IsKeyContext() {}

func NewKeyContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *KeyContext {
	var p = new(KeyContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = EqlParserRULE_key

	return p
}

func (s *KeyContext) GetParser() antlr.Parser { return s.parser }

func (s *KeyContext) Constant() IConstantContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IConstantContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(IConstantContext)
}

func (s *KeyContext) NAME() antlr.TerminalNode {
	return s.GetToken(EqlParserNAME, 0)
}

func (s *KeyContext) STEXT() antlr.TerminalNode {
	return s.GetToken(EqlParserSTEXT, 0)
}

func (s *KeyContext) DTEXT() antlr.TerminalNode {
	return s.GetToken(EqlParserDTEXT, 0)
}

func (s *KeyContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *KeyContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *KeyContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.EnterKey(s)
	}
}

func (s *KeyContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.ExitKey(s)
	}
}

func (s *KeyContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case EqlVisitor:
		return t.VisitKey(s)

	default:
		return t.VisitChildren(s)
	}
}

func (p *EqlParser) Key() (localctx IKeyContext) {
	this := p
	_ = this

	localctx = NewKeyContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 16, EqlParserRULE_key)
	var _la int

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(129)
		_la = p.GetTokenStream().LA(1)

		if !((int64(_la) & ^0x3f) == 0 && ((int64(1)<<_la)&109051904) != 0) {
			p.GetErrorHandler().RecoverInline(p)
		} else {
			p.GetErrorHandler().ReportMatch(p)
			p.Consume()
		}
	}
	{
		p.SetState(130)
		p.Match(EqlParserT__2)
	}
	{
		p.SetState(131)
		p.Constant()
	}

	return localctx
}

// IDictContext is an interface to support dynamic dispatch.
type IDictContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// Getter signatures
	AllKey() []IKeyContext
	Key(i int) IKeyContext

	// IsDictContext differentiates from other interfaces.
	IsDictContext()
}

type DictContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyDictContext() *DictContext {
	var p = new(DictContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = EqlParserRULE_dict
	return p
}

func (*DictContext) IsDictContext() {}

func NewDictContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *DictContext {
	var p = new(DictContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = EqlParserRULE_dict

	return p
}

func (s *DictContext) GetParser() antlr.Parser { return s.parser }

func (s *DictContext) AllKey() []IKeyContext {
	children := s.GetChildren()
	len := 0
	for _, ctx := range children {
		if _, ok := ctx.(IKeyContext); ok {
			len++
		}
	}

	tst := make([]IKeyContext, len)
	i := 0
	for _, ctx := range children {
		if t, ok := ctx.(IKeyContext); ok {
			tst[i] = t.(IKeyContext)
			i++
		}
	}

	return tst
}

func (s *DictContext) Key(i int) IKeyContext {
	var t antlr.RuleContext
	j := 0
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IKeyContext); ok {
			if j == i {
				t = ctx.(antlr.RuleContext)
				break
			}
			j++
		}
	}

	if t == nil {
		return nil
	}

	return t.(IKeyContext)
}

func (s *DictContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *DictContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *DictContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.EnterDict(s)
	}
}

func (s *DictContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(EqlListener); ok {
		listenerT.ExitDict(s)
	}
}

func (s *DictContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case EqlVisitor:
		return t.VisitDict(s)

	default:
		return t.VisitChildren(s)
	}
}

func (p *EqlParser) Dict() (localctx IDictContext) {
	this := p
	_ = this

	localctx = NewDictContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 18, EqlParserRULE_dict)
	var _la int

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(133)
		p.Key()
	}
	p.SetState(138)
	p.GetErrorHandler().Sync(p)
	_la = p.GetTokenStream().LA(1)

	for _la == EqlParserT__1 {
		{
			p.SetState(134)
			p.Match(EqlParserT__1)
		}
		{
			p.SetState(135)
			p.Key()
		}

		p.SetState(140)
		p.GetErrorHandler().Sync(p)
		_la = p.GetTokenStream().LA(1)
	}

	return localctx
}

func (p *EqlParser) Sempred(localctx antlr.RuleContext, ruleIndex, predIndex int) bool {
	switch ruleIndex {
	case 5:
		var t *ExpContext = nil
		if localctx != nil {
			t = localctx.(*ExpContext)
		}
		return p.Exp_Sempred(t, predIndex)

	default:
		panic("No predicate with index: " + fmt.Sprint(ruleIndex))
	}
}

func (p *EqlParser) Exp_Sempred(localctx antlr.RuleContext, predIndex int) bool {
	this := p
	_ = this

	switch predIndex {
	case 0:
		return p.Precpred(p.GetParserRuleContext(), 19)

	case 1:
		return p.Precpred(p.GetParserRuleContext(), 18)

	case 2:
		return p.Precpred(p.GetParserRuleContext(), 16)

	case 3:
		return p.Precpred(p.GetParserRuleContext(), 15)

	case 4:
		return p.Precpred(p.GetParserRuleContext(), 14)

	case 5:
		return p.Precpred(p.GetParserRuleContext(), 13)

	case 6:
		return p.Precpred(p.GetParserRuleContext(), 12)

	case 7:
		return p.Precpred(p.GetParserRuleContext(), 11)

	case 8:
		return p.Precpred(p.GetParserRuleContext(), 10)

	case 9:
		return p.Precpred(p.GetParserRuleContext(), 9)

	default:
		panic("No predicate with index: " + fmt.Sprint(predIndex))
	}
}
