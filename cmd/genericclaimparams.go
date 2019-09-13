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
	"sort"
	"strings"

	"github.com/nats-io/nsc/cmd/store"

	"github.com/nats-io/jwt"
)

// GenericClaimsParams - TimeParams and tags
type GenericClaimsParams struct {
	TimeParams
	tags   []string
	rmTags []string
}

func (sp *GenericClaimsParams) Edit() error {
	if err := sp.TimeParams.Edit(); err != nil {
		return err
	}

	return nil
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
