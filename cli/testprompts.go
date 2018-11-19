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

package cli

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

func (t *TestPrompts) Prompt(label string, value string, edit bool, validator Validator) (string, error) {
	val := t.inputs[t.count].(string)
	t.count = t.count + 1

	if validator != nil {
		err := validator(val)
		if err != nil {
			return Prompt(label, value, edit, validator)
		}
	}
	return val, nil
}

func (t *TestPrompts) PromptYN(m string, defaultValue bool) (bool, error) {
	val := t.inputs[t.count].(bool)
	t.count = t.count + 1
	return val, nil
}

func (t *TestPrompts) PromptSecret(m string) (string, error) {
	val := t.inputs[t.count].(string)
	t.count = t.count + 1
	return val, nil
}

func (t *TestPrompts) PromptChoices(m string, choices []string) (int, error) {
	val := t.inputs[t.count].(int)
	t.count = t.count + 1
	return val, nil
}

func (t *TestPrompts) PromptMultipleChoices(m string, choices []string) ([]int, error) {
	val := t.inputs[t.count].([]int)
	t.count = t.count + 1
	return val, nil
}
