// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runtime

import (
	"fmt"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent/internal/pkg/core/authority"
	"github.com/elastic/elastic-agent/pkg/component"
)

func (m *Manager) connectShippers(components []component.Component) error {
	// ensure that all shipper components have created connection information (must happen before we connect the units)
	shippersTouched := make(map[string]bool)
	for i, comp := range components {
		if comp.ShipperSpec != nil {
			// running shipper (ensure connection information is created)
			shippersTouched[comp.ID] = true
			conn, ok := m.shipperConns[comp.ID]
			if !ok {
				ca, err := authority.NewCA()
				if err != nil {
					return fmt.Errorf("failed to create connection CA for shipper %q: %w", comp.ID, err)
				}
				conn = &shipperConn{
					addr:  getShipperAddr(comp.ID),
					ca:    ca,
					pairs: make(map[string]*authority.Pair),
				}
				m.shipperConns[comp.ID] = conn
			}

			// each input unit needs its corresponding
			pairsTouched := make(map[string]bool)
			for j, unit := range comp.Units {
				if unit.Type == client.UnitTypeInput {
					pairsTouched[unit.ID] = true
					pair, err := pairGetOrCreate(conn, unit.ID)
					if err != nil {
						return fmt.Errorf("failed to get/create certificate pait for shipper %q/%q: %w", comp.ID, unit.ID, err)
					}
					cfg, cfgErr := injectShipperConn(unit.Config, conn.addr, conn.ca, pair)
					unit.Config = cfg
					unit.Err = cfgErr
					comp.Units[j] = unit
				}
			}

			// cleanup any pairs that are no-longer used
			for pairID := range conn.pairs {
				touch := pairsTouched[pairID]
				if !touch {
					delete(conn.pairs, pairID)
				}
			}
			components[i] = comp
		}
	}

	// cleanup any shippers that are no-longer used
	for shipperID := range m.shipperConns {
		touch := shippersTouched[shipperID]
		if !touch {
			delete(m.shipperConns, shipperID)
		}
	}

	// connect the output units with the same connection information
	for i, comp := range components {
		if comp.ShipperRef != nil {
			conn, ok := m.shipperConns[comp.ShipperRef.ComponentID]
			if !ok {
				return fmt.Errorf("component %q references a non-existing shipper %q", comp.ID, comp.ShipperRef.ComponentID)
			}
			pair, ok := conn.pairs[comp.ID]
			if !ok {
				return fmt.Errorf("component %q references shipper %q that doesn't know about the component", comp.ID, comp.ShipperRef.ComponentID)
			}
			for j, unit := range comp.Units {
				if unit.Type == client.UnitTypeOutput {
					cfg, cfgErr := injectShipperConn(unit.Config, conn.addr, conn.ca, pair)
					unit.Config = cfg
					unit.Err = cfgErr
					comp.Units[j] = unit
				}
			}
			components[i] = comp
		}
	}

	return nil
}

func pairGetOrCreate(conn *shipperConn, pairID string) (*authority.Pair, error) {
	var err error
	pair, ok := conn.pairs[pairID]
	if ok {
		return pair, nil
	}
	pair, err = conn.ca.GeneratePairWithName(pairID)
	if err != nil {
		return nil, err
	}
	conn.pairs[pairID] = pair
	return pair, nil
}

func injectShipperConn(cfg *proto.UnitExpectedConfig, addr string, ca *authority.CertificateAuthority, pair *authority.Pair) (*proto.UnitExpectedConfig, error) {
	if cfg == nil {
		// unit configuration had an error generating (do nothing)
		return cfg, nil
	}
	source := cfg.Source.AsMap()
	source["server"] = addr
	source["ssl"] = map[string]interface{}{
		"certificate_authorities": []interface{}{
			string(ca.Crt()),
		},
		"certificate": string(pair.Crt),
		"key":         string(pair.Key),
	}
	return component.ExpectedConfig(source)
}
