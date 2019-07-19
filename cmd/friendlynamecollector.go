/*
 * Copyright 2018-2019 The NATS Authors
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

	"github.com/nats-io/nsc/cmd/store"
)

// NewFriendlyNameCollector returns a map of public keys to
// friendly names - if resources from outside the current
// operator are returned as <operator>/<name>
func friendlyNames(operator string) (map[string]string, error) {
	m := make(map[string]string)
	operators := config.ListOperators()
	hasMany := len(operators) > 1
	for _, o := range operators {
		if o == "" {
			continue
		}
		s, err := config.LoadStore(o)
		if err != nil {
			return nil, err
		}
		oc, err := s.ReadOperatorClaim()
		if err != nil {
			continue
		}
		m[oc.Subject] = oc.Name
		for _, sk := range oc.SigningKeys {
			m[sk] = oc.Name
		}
		accounts, err := s.ListSubContainers(store.Accounts)
		if err != nil {
			return nil, err
		}
		for _, a := range accounts {
			ac, err := s.ReadAccountClaim(a)
			if err != nil {
				return nil, err
			}
			name := ac.Name
			if hasMany && oc.Name != operator {
				name = fmt.Sprintf("%s/%s", oc.Name, ac.Name)
			}
			m[ac.Subject] = name
			for _, sk := range ac.SigningKeys {
				m[sk] = name
			}
		}
	}
	return m, nil
}
