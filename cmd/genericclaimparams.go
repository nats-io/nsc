/*
 *
 *  * Copyright 2018-2019 The NATS Authors
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  * http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package cmd

import (
	"fmt"
	"sort"
	"strings"

	cli "github.com/nats-io/cliprompts/v2"
	"github.com/nats-io/jwt"
	"github.com/nats-io/nsc/cmd/store"
)

// GenericClaimsParams - TimeParams and tags
type GenericClaimsParams struct {
	TimeParams
	tags   []string
	rmTags []string
}

func (sp *GenericClaimsParams) Edit(current []string) error {
	var err error
	if err := sp.TimeParams.Edit(); err != nil {
		return err
	}
	sp.rmTags, err = sp.remove("tags", current)
	if err != nil {
		return err
	}
	sp.tags, err = sp.add("tags", current)
	if err != nil {
		return err
	}
	return nil
}

func (sp *GenericClaimsParams) add(label string, current []string) ([]string, error) {
	first := true
	var values []string
	for {
		m := fmt.Sprintf("add a %s", label)
		if !first || len(current) > 0 {
			m = fmt.Sprintf("add another %s", label)
		}
		first = false
		ok, err := cli.Confirm(m, false)
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
		v, err := cli.Prompt(fmt.Sprintf("enter a %s", label), "")
		if err != nil {
			return nil, err
		}
		values = append(values, v)
	}
	return values, nil
}

func (sp *GenericClaimsParams) remove(label string, values []string) ([]string, error) {
	var remove []string
	if len(values) == 0 {
		return nil, nil
	}
	ok, err := cli.Confirm("remove tags", false)
	if err != nil {
		return nil, err
	}
	if ok {
		idx, err := cli.MultiSelect(fmt.Sprintf("select %s to remove", label), values)
		if err != nil {
			return nil, err
		}
		for _, v := range idx {
			remove = append(remove, values[v])
		}
	}
	return remove, nil
}

func (sp *GenericClaimsParams) Valid() error {
	if err := sp.TimeParams.Validate(); err != nil {
		return err
	}
	return nil
}

func (sp *GenericClaimsParams) Run(ctx ActionCtx, claim jwt.Claims, r *store.Report) error {
	cd := claim.Claims()
	if sp.TimeParams.IsStartChanged() {
		ov := cd.NotBefore
		cd.NotBefore, _ = sp.TimeParams.StartDate()
		if r != nil && ov != cd.NotBefore {
			if cd.NotBefore == 0 {
				r.AddOK("changed jwt start to not have a start date")
			} else {
				r.AddOK("changed jwt valid start to %s - %s", UnixToDate(cd.NotBefore), strings.ToLower(HumanizedDate(cd.NotBefore)))
			}
		}
	}

	if sp.TimeParams.IsExpiryChanged() {
		ov := cd.Expires
		cd.Expires, _ = sp.TimeParams.ExpiryDate()
		if r != nil && ov != cd.Expires {
			if cd.Expires == 0 {
				r.AddOK("changed jwt expiry to never expire")
			} else {
				r.AddOK("changed jwt expiry to %s - %s", UnixToDate(cd.Expires), strings.ToLower(HumanizedDate(cd.Expires)))
			}
		}
	}

	cd.Tags.Add(sp.tags...)
	cd.Tags.Remove(sp.rmTags...)
	sort.Strings(cd.Tags)

	if r != nil {
		for _, t := range sp.tags {
			r.AddOK("added tag %q", strings.ToLower(t))
		}
		for _, t := range sp.rmTags {
			r.AddOK("removed tag %q", strings.ToLower(t))
		}
	}
	sort.Strings(cd.Tags)
	return nil
}
