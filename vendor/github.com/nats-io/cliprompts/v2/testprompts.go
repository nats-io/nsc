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
	"fmt"
	"strings"
)

type TestPrompts struct {
	count  int
	inputs []interface{}
}

func NewTestPrompts(inputs []interface{}) PromptLib {
	return &TestPrompts{
		count:  0,
		inputs: inputs,
	}
}

func (t *TestPrompts) logInputs(kind string, label string, value interface{}) {
	if LogFn == nil {
		return
	}
	LogFn(fmt.Sprintf("[%s %d] %s = %v\n", kind, t.count, label, value))
}

func (t *TestPrompts) Prompt(label string, value string, o ...Opt) (string, error) {
	val, ok := t.inputs[t.count].(string)
	if !ok {
		return "", fmt.Errorf("%s prompt expected a string: %v", label, t.inputs[t.count])
	}
	t.logInputs("prompt", label, t.inputs[t.count])
	t.count = t.count + 1

	opts := processOpts(o...)
	if opts.Fn != nil {
		if err := opts.Fn(val); err != nil {
			return "", err
		}
	}
	return val, nil
}

func (t *TestPrompts) Confirm(m string, v bool, o ...Opt) (bool, error) {
	val, ok := t.inputs[t.count].(bool)
	if !ok {
		return false, fmt.Errorf("%s confirm expected a bool: %v", m, t.inputs[t.count])
	}
	t.logInputs("confirm", m, t.inputs[t.count])
	t.count = t.count + 1
	return val, nil
}

func (t *TestPrompts) Password(m string, o ...Opt) (string, error) {
	val, ok := t.inputs[t.count].(string)
	if !ok {
		return "", fmt.Errorf("%s password expected a string: %v", m, t.inputs[t.count])
	}
	t.logInputs("password", m, t.inputs[t.count])

	opts := processOpts(o...)
	if opts.Fn != nil {
		if err := opts.Fn(val); err != nil {
			return "", err
		}
	}

	t.count = t.count + 1
	return val, nil
}

func (t *TestPrompts) Select(m string, value string, choices []string, o ...Opt) (int, error) {
	val, ok := t.inputs[t.count].(int)
	if !ok {
		return -1, fmt.Errorf("%s select expected an int: %v", m, t.inputs[t.count])
	}
	t.logInputs("select", m, fmt.Sprintf("[%s]", strings.Join(choices, ",\n\t")))
	t.logInputs("select", "   selection", fmt.Sprintf("%d (%s)", val, choices[val]))
	t.count = t.count + 1
	return val, nil
}

func (t *TestPrompts) MultiSelect(m string, choices []string, o ...Opt) ([]int, error) {
	val, ok := t.inputs[t.count].([]int)
	if !ok {
		return nil, fmt.Errorf("%s multiselect expected []int: %v", m, t.inputs[t.count])
	}
	t.logInputs("multiselect", m, t.inputs[t.count])
	t.count = t.count + 1
	return val, nil
}
