/*
 * Copyright 2018 The NATS Authors
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nsc/cmd/store"
)

func LoadActivation(jti string) (*jwt.ActivationClaims, error) {
	s, err := getStore()
	if err != nil {
		return nil, err
	}

	d, err := s.Read(filepath.Join(store.Activations, jti+".jwt"))
	if err != nil {
		return nil, err
	}
	ac, err := jwt.DecodeActivationClaims(string(d))
	if err != nil {
		return nil, err
	}
	return ac, err
}

func ListActivations() ([]string, error) {
	s, err := getStore()
	if err != nil {
		return nil, err
	}

	a, err := s.List(store.Activations, ".jwt")
	if err != nil {
		return nil, err
	}

	if len(a) == 0 {
		return a, nil
	}

	for i, p := range a {
		d, err := s.Read(filepath.Join(store.Activations, p))
		if err != nil {
			return nil, err
		}
		a[i] = string(d)
	}
	return a, nil
}

func ParseActivations(tokens []string) ([]*jwt.ActivationClaims, error) {
	var activations []*jwt.ActivationClaims
	for _, t := range tokens {
		c, err := jwt.DecodeActivationClaims(t)
		if err != nil {
			return nil, err
		}
		activations = append(activations, c)
	}
	return activations, nil
}

func ActivationLabels(activations []*jwt.ActivationClaims) []string {
	var labels []string
	for _, c := range activations {
		labels = append(labels, fmt.Sprintf("%s\t%s", c.Name, c.ID))
	}
	return labels
}
