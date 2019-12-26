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

package cliprompts

import (
	"github.com/AlecAivazis/survey/v2"
)

type SurveyUI struct{}

func (sui *SurveyUI) Prompt(label string, value string, o ...Opt) (string, error) {
	v := value
	p := &survey.Input{
		Message: label,
		Default: value,
	}

	opts := processOpts(o...)
	if opts.Help != "" {
		p.Help = opts.Help
	}
	if err := survey.AskOne(p, &v, survey.WithValidator(sui.wrap(opts.Fn))); err != nil {
		return "", err
	}
	return v, nil
}

func (sui *SurveyUI) wrap(validator Validator) survey.Validator {
	if validator == nil {
		validator = func(_ string) error {
			return nil
		}
	}
	return func(input interface{}) error {
		s := input.(string)
		return validator(s)
	}
}

func (sui *SurveyUI) Confirm(m string, defaultValue bool, o ...Opt) (bool, error) {
	v := defaultValue
	p := &survey.Confirm{
		Message: m,
		Default: defaultValue,
	}
	opts := processOpts(o...)
	if opts.Help != "" {
		p.Help = opts.Help
	}

	if err := survey.AskOne(p, &v); err != nil {
		return false, err
	}
	return v, nil
}

func (sui *SurveyUI) Password(m string, o ...Opt) (string, error) {
	v := ""
	p := &survey.Password{
		Message: m,
	}

	opts := processOpts(o...)
	if opts.Help != "" {
		p.Help = opts.Help
	}

	if err := survey.AskOne(p, &v, survey.WithValidator(sui.wrap(opts.Fn))); err != nil {
		return "", err
	}
	return v, nil
}

func (sui *SurveyUI) Select(m string, value string, choices []string, o ...Opt) (int, error) {
	var v int

	if value == "" && len(choices) > 0 {
		value = choices[0]
	}
	p := &survey.Select{
		Message: m,
		Options: choices,
		Default: value,
	}
	opts := processOpts(o...)
	if opts.Help != "" {
		p.Help = opts.Help
	}

	if err := survey.AskOne(p, &v); err != nil {
		return -1, err
	}
	return v, nil
}

func (sui *SurveyUI) MultiSelect(m string, choices []string, o ...Opt) ([]int, error) {
	var idx []int
	p := &survey.MultiSelect{
		Message: m,
		Options: choices,
	}

	opts := processOpts(o...)
	if opts.Help != "" {
		p.Help = opts.Help
	}

	if err := survey.AskOne(p, &idx); err != nil {
		return nil, err
	}

	return idx, nil
}
