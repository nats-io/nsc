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
	"regexp"
	"strconv"
	"time"

	cli "github.com/nats-io/cliprompts/v2"
	"github.com/spf13/cobra"
)

type TimeParams struct {
	Start  string
	Expiry string
}

func (p *TimeParams) BindFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&p.Start, "start", "", "0", "valid from ('0' is always, '3d' is three days) - yyyy-mm-dd, #m(inutes), #h(ours), #d(ays), #w(eeks), #M(onths), #y(ears)")
	cmd.Flags().StringVarP(&p.Expiry, "expiry", "", "0", "valid until ('0' is always, '2M' is two months) - yyyy-mm-dd, #m(inutes), #h(ours), #d(ays), #w(eeks), #M(onths), #y(ears)")
}

func (p *TimeParams) valid(value string, label string, oldOK bool) error {
	now := time.Now().Unix()
	when, err := ParseExpiry(value)
	if err != nil {
		return fmt.Errorf("%s %q is invalid: %v", label, value, err)
	}
	if InteractiveFlag && !oldOK && when != 0 && now > when {
		m := fmt.Sprintf("%s %q is in the past (%s) - are you sure?", label, value, HumanizedDate(when))
		ok, err := cli.Confirm(m, false)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%s %q is in the past (%s)", label, value, HumanizedDate(when))
		}
	}
	return nil
}

func (p *TimeParams) ValidateStart() error {
	if err := p.valid(p.Start, "start", true); err != nil {
		return err
	}
	return nil
}

func (p *TimeParams) ValidateExpiry() error {
	if err := p.valid(p.Expiry, "expiry", false); err != nil {
		return err
	}
	return nil
}

func (p *TimeParams) IsStartChanged() bool {
	return p.Start != ""
}

func (p *TimeParams) IsExpiryChanged() bool {
	return p.Expiry != ""
}

func (p *TimeParams) Validate() error {
	if err := p.ValidateStart(); err != nil {
		return err
	}
	if err := p.ValidateExpiry(); err != nil {
		return err
	}
	return nil
}

func (p *TimeParams) canParse(s string) error {
	_, err := ParseExpiry(s)
	if err != nil {
		return fmt.Errorf("%s is invalid: %v", s, err)
	}
	return nil
}

func (p *TimeParams) Edit() error {
	var err error
	format := "valid from ('0' is always) - yyyy-mm-dd, #m(inutes), #h(ours), #d(ays), #w(eeks), #M(onths), #y(ears)"
	p.Start, err = cli.Prompt("valid", p.Start, cli.Val(p.canParse), cli.Help(format))
	if err != nil {
		return err
	}

	p.Expiry, err = cli.Prompt("valid until (0 is always)", p.Expiry, cli.Val(p.canParse), cli.Help(format))
	return err
}

func (p *TimeParams) StartDate() (int64, error) {
	return ParseExpiry(p.Start)
}

func (p *TimeParams) ExpiryDate() (int64, error) {
	return ParseExpiry(p.Expiry)
}

// parse expiration argument - supported are YYYY-MM-DD for absolute, and relative
// (m)inute, (h)our, (d)ay, (w)week, (M)onth, (y)ear expressions
func ParseExpiry(s string) (int64, error) {
	if s == "" || s == "0" {
		return 0, nil
	}
	// try to parse directly
	t, err := time.Parse("2006-01-02 15:04:05 UTC", s)
	if err == nil {
		return t.Unix(), nil
	}

	re := regexp.MustCompile(`(\d){4}-(\d){2}-(\d){2}`)
	if re.MatchString(s) {
		t, err := time.Parse("2006-01-02", s)
		if err != nil {
			return 0, err
		}
		return t.Unix(), nil
	}

	re = regexp.MustCompile(`(?P<count>-?\d+)(?P<qualifier>[mhdMyw])`)
	m := re.FindStringSubmatch(s)
	if m != nil {
		v, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil {
			return 0, err
		}
		count := int(v)
		if count == 0 {
			return 0, nil
		}
		dur := time.Duration(count)
		now := time.Now()
		switch m[2] {
		case "m":
			return now.Add(dur * time.Minute).Unix(), nil
		case "h":
			return now.Add(dur * time.Hour).Unix(), nil
		case "d":
			return now.AddDate(0, 0, count).Unix(), nil
		case "w":
			return now.AddDate(0, 0, 7*count).Unix(), nil
		case "M":
			return now.AddDate(0, count, 0).Unix(), nil
		case "y":
			return now.AddDate(count, 0, 0).Unix(), nil
		default:
			return 0, fmt.Errorf("unknown interval %q in %q", m[2], m[0])
		}
	}
	return 0, fmt.Errorf("couldn't parse expiry: %v", s)
}
