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
	"bytes"
	"fmt"

	"github.com/mitchellh/go-wordwrap"
)

func WrapString(lim uint, s string) string {
	return wordwrap.WrapString(s, lim)
}

func WrapSprintf(lim uint, format string, a ...interface{}) string {
	return WrapString(lim, fmt.Sprintf(format, a...))
}

func Wrap(lim uint, args ...interface{}) string {
	var buf bytes.Buffer
	for i, arg := range args {
		if i > 0 {
			buf.WriteByte(' ')
		}
		buf.WriteString(fmt.Sprintf("%v", arg))
	}

	return WrapString(lim, buf.String())
}
