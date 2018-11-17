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
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cli"
	"github.com/nats-io/nsc/cmd/store"
)

// Resolve a directory/file from an environment variable
// if not set defaultPath is returned
func ResolvePath(defaultPath string, varName string) string {
	v := os.Getenv(varName)
	if v != "" {
		return v
	}
	return defaultPath
}

func GetOutput(fp string) (*os.File, error) {
	var err error
	var f *os.File

	if fp == "--" {
		f = os.Stdout
	} else {
		_, err = os.Stat(fp)
		if err == nil {
			return nil, fmt.Errorf("%q already exists", fp)
		}
		if !os.IsNotExist(err) {
			return nil, err
		}

		f, err = os.Create(fp)
		if err != nil {
			return nil, fmt.Errorf("error creating output file %q: %v", fp, err)
		}
	}
	return f, nil
}

func IsStdOut(fp string) bool {
	return fp == "--"
}

func Write(fp string, data []byte) error {
	var err error
	var f *os.File

	f, err = GetOutput(fp)
	if err != nil {
		return err
	}
	if !IsStdOut(fp) {
		defer f.Close()
	}
	_, err = f.Write(data)
	if err != nil {
		return fmt.Errorf("error writing %q: %v", fp, err)
	}

	if !IsStdOut(fp) {
		if err := f.Sync(); err != nil {
			return err
		}
	}
	return nil
}

func FormatKeys(keyType string, publicKey string, privateKey string) []byte {
	w := bytes.NewBuffer(nil)
	label := strings.ToUpper(keyType)

	if privateKey != "" {
		fmt.Fprintln(w, "************************* IMPORTANT *************************")
		fmt.Fprintln(w, "Your options generated NKEYs which can be used to create")
		fmt.Fprintln(w, "entities or prove identity.")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Generated keys printed below are sensitive and should be")
		fmt.Fprintln(w, "treated as secrets to prevent unauthorized access.")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "The private key is not saved by the tool. Please save")
		fmt.Fprintln(w, "it now as it will be required by the user to connect to NATS.")
		fmt.Fprintln(w, "The public key is saved and uniquely identifies the user.")
		fmt.Fprintln(w)

		fmt.Fprintf(w, "-----BEGIN %s PRIVATE KEY-----\n", label)
		fmt.Fprintln(w, privateKey)
		fmt.Fprintf(w, "------END %s PRIVATE KEY------\n", label)
		fmt.Fprintln(w)

		fmt.Fprintln(w, "*************************************************************")
		fmt.Fprintln(w)
	}

	if publicKey != "" {
		fmt.Fprintf(w, "-----BEGIN %s PUB KEY-----\n", label)
		fmt.Fprintln(w, publicKey)
		fmt.Fprintf(w, "------END %s PUB KEY------\n", label)
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w)

	return w.Bytes()
}

func FormatJwt(jwtType string, jwt string) []byte {
	w := bytes.NewBuffer(nil)

	label := strings.ToUpper(jwtType)
	fmt.Fprintf(w, "-----BEGIN %s JWT-----\n", label)
	fmt.Fprintln(w, jwt)
	fmt.Fprintf(w, "------END %s JWT------\n", label)
	fmt.Fprintln(w)

	return w.Bytes()
}

func ExtractToken(s string) string {
	// remove all the spaces
	re := regexp.MustCompile(`\s+`)
	w := re.ReplaceAllString(s, "")
	// remove multiple dashes
	re = regexp.MustCompile(`\-+`)
	w = re.ReplaceAllString(w, "-")

	// the token can now look like
	// -BEGINXXXXPUBKEY-token-ENDXXXXPUBKEY-
	re = regexp.MustCompile(`(?m)(\-BEGIN.+(JWT|KEY)\-)(?P<token>.+)(\-END.+(JWT|KEY)\-)`)
	// find the index of the token
	m := re.FindStringSubmatch(w)
	if len(m) > 0 {
		for i, name := range re.SubexpNames() {
			if name == "token" {
				return m[i]
			}
		}
	}
	return s
}

func ParseNumber(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	s = strings.ToUpper(s)
	re := regexp.MustCompile(`(\d+$)`)
	m := re.FindStringSubmatch(s)
	if m != nil {
		v, err := strconv.ParseInt(m[0], 10, 64)
		if err != nil {
			return 0, err
		}
		return v, nil
	}
	re = regexp.MustCompile(`(\d+)([K|M|G])`)
	m = re.FindStringSubmatch(s)
	if m != nil {
		v, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil {
			return 0, err
		}
		if m[2] == "K" {
			return v * 1000, nil
		}
		if m[2] == "M" {
			return v * 1000000, nil
		}
		if m[2] == "G" {
			return v * 1000000000, nil
		}
	}
	return 0, fmt.Errorf("couldn't parse number: %v", s)
}

func UnixToDate(d int64) string {
	if d == 0 {
		return ""
	}
	return time.Unix(d, 0).UTC().String()
}

func HumanizedDate(d int64) string {
	if d == 0 {
		return ""
	}
	now := time.Now()
	when := time.Unix(d, 0).UTC()

	if now.After(when) {
		return strings.TrimSpace(strings.Title(humanize.RelTime(when, now, "ago", "")))
	} else {
		return strings.TrimSpace(strings.Title("in " + humanize.RelTime(now, when, "", "")))
	}
}

func NKeyValidator(kind nkeys.PrefixByte) cli.Validator {
	return func(v string) error {
		nk, err := store.ResolveKey(v)
		if err != nil {
			return err
		}
		t, err := store.KeyType(nk)
		if err != nil {
			return err
		}
		if t != kind {
			return fmt.Errorf("specified key is not valid for an %s", store.KeyTypeLabel(kind))
		}
		return nil
	}
}

func EditKeyPath(kind nkeys.PrefixByte, label string, keypath *string) error {
	ok, err := cli.PromptYN(fmt.Sprintf("generate an %s nkey", label))
	if err != nil {
		return err
	}

	if !ok {
		v, err := cli.Prompt(fmt.Sprintf("path to the %s nkey", label), "", true, NKeyValidator(kind))
		if err != nil {
			return err
		}
		*keypath = v
	}
	return nil
}
