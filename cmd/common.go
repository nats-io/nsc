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
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/dustin/go-humanize"
	"github.com/mitchellh/go-homedir"
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
	var f *os.File

	if fp == "--" {
		f = os.Stdout
	} else {
		afp, err := filepath.Abs(fp)
		if err != nil {
			return nil, fmt.Errorf("error calculating abs %q: %v", fp, err)
		}
		_, err = os.Stat(afp)
		if err == nil {
			return nil, fmt.Errorf("%q already exists", afp)
		}
		if !os.IsNotExist(err) {
			return nil, err
		}

		f, err = os.Create(afp)
		if err != nil {
			return nil, fmt.Errorf("error creating output file %q: %v", afp, err)
		}
	}
	return f, nil
}

func IsStdOut(fp string) bool {
	return fp == "--"
}

func WriteJson(fp string, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("error marshaling: %v", err)
	}

	if err := ioutil.WriteFile(fp, data, 0600); err != nil {
		return fmt.Errorf("error writing %q: %v", fp, err)
	}

	return nil
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

func ReadJson(fp string, v interface{}) error {
	data, err := Read(fp)
	if err != nil {
		return err
	}
	err = json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	return nil
}

func Read(fp string) ([]byte, error) {
	hfp, err := homedir.Expand(fp)
	if err != nil {
		return nil, fmt.Errorf("error expanding path %q: %v", fp, err)
	}
	afp, err := filepath.Abs(hfp)
	if err != nil {
		return nil, fmt.Errorf("error converting abs %q: %v", fp, err)
	}

	return ioutil.ReadFile(afp)
}

func FormatConfig(jwtType string, jwtString string, seed string) []byte {
	w := bytes.NewBuffer(nil)

	w.Write(FormatJwt(jwtType, jwtString))

	_, _ = fmt.Fprintln(w, "************************* IMPORTANT *************************")
	_, _ = fmt.Fprintln(w, "NKEY Seed printed below can be used to sign and prove identity.")
	_, _ = fmt.Fprintln(w, "NKEYs are sensitive and should be treated as secrets.")
	_, _ = fmt.Fprintln(w)

	label := strings.ToUpper(jwtType)
	_, _ = fmt.Fprintf(w, "-----BEGIN %s NKEY SEED-----\n", label)
	_, _ = fmt.Fprintln(w, seed)
	_, _ = fmt.Fprintf(w, "------END %s NKEY SEED------\n", label)
	_, _ = fmt.Fprintln(w)

	_, _ = fmt.Fprintln(w, "*************************************************************")

	return w.Bytes()
}

func FormatJwt(jwtType string, jwtString string) []byte {
	w := bytes.NewBuffer(nil)

	label := strings.ToUpper(jwtType)
	_, _ = fmt.Fprintf(w, "-----BEGIN NATS %s JWT-----\n", label)
	_, _ = fmt.Fprintln(w, jwtString)
	_, _ = fmt.Fprintf(w, "------END NATS %s JWT------\n", label)
	_, _ = fmt.Fprintln(w)
	return w.Bytes()
}

func ExtractToken(s string) (string, bool) {
	lines := strings.Split(s, "\n")
	start := -1
	end := -1
	for i, v := range lines {
		if strings.HasPrefix(v, "-----BEGIN ") && strings.HasSuffix(v, " JWT-----") {
			start = i + 1
			continue
		}
		if strings.HasPrefix(v, "------END ") && strings.HasSuffix(v, " JWT------") {
			end = i
			break
		}
	}

	if start != -1 && end != -1 {
		lines := lines[start:end]
		return strings.Join(lines, ""), true
	}
	return s, false
}

func ExtractSeed(s string) (nkeys.KeyPair, error) {
	lines := strings.Split(s, "\n")
	start := -1
	end := -1
	for i, v := range lines {
		if strings.HasPrefix(v, "-----BEGIN ") && strings.HasSuffix(v, " SEED-----") {
			start = i + 1
			continue
		}
		if strings.HasPrefix(v, "------END ") && strings.HasSuffix(v, " SEED------") {
			end = i
			break
		}
	}

	if start != -1 && end != -1 {
		lines := lines[start:end]
		s = strings.Join(lines, "")
	}
	return nkeys.FromSeed([]byte(s))
}

func ParseNumber(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	s = strings.ToUpper(s)
	re := regexp.MustCompile(`(-?\d+$)`)
	m := re.FindStringSubmatch(s)
	if m != nil {
		v, err := strconv.ParseInt(m[0], 10, 64)
		if err != nil {
			return 0, err
		}
		return v, nil
	}
	re = regexp.MustCompile(`(-?\d+)([BKMG])`)
	m = re.FindStringSubmatch(s)
	if m != nil {
		v, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil {
			return 0, err
		}
		if v < 0 {
			return -1, nil
		}
		if m[2] == "B" {
			return v, nil
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

	return strings.Replace(time.Unix(d, 0).UTC().String(), " +0000", "", -1)
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

func RenderDate(d int64) string {
	if d == 0 {
		return ""
	}

	return UnixToDate(d)
}

func NKeyValidator(kind nkeys.PrefixByte) cli.Validator {
	return func(v string) error {
		if v == "" {
			return fmt.Errorf("value cannot be empty")
		}
		nk, err := store.ResolveKey(v)
		if err != nil {
			return err
		}
		if nk == nil {
			// if it looks like a file, provide a better message
			if strings.Contains(v, string(os.PathSeparator)) {
				_, err := os.Stat(v)
				if err != nil {
					return err
				}
			}
			return fmt.Errorf("%q is not a valid nkey", v)
		}
		t, err := store.KeyType(nk)
		if err != nil {
			return err
		}
		if t != kind {
			return fmt.Errorf("specified key is not valid for an %s", kind.String())
		}
		return nil
	}
}

func SeedNKeyValidatorMatching(kind nkeys.PrefixByte, pukeys []string) cli.Validator {
	return func(v string) error {
		if v == "" {
			return fmt.Errorf("value cannot be empty")
		}
		nk, err := store.ResolveKey(v)
		if err != nil {
			return err
		}
		if nk == nil {
			// if it looks like a file, provide a better message
			if strings.Contains(v, string(os.PathSeparator)) {
				_, err := os.Stat(v)
				if err != nil {
					return err
				}
			}
			return fmt.Errorf("%q is not a valid nkey", v)
		}
		t, err := store.KeyType(nk)
		if err != nil {
			return err
		}
		if t != kind {
			return fmt.Errorf("specified key is not valid for an %s", kind.String())
		}

		pk, err := nk.PublicKey()
		if err != nil {
			return fmt.Errorf("error extracting public key: %v", err)
		}

		found := false
		for _, k := range pukeys {
			if k == pk {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%q is not an expected signing key %v", v, pukeys)
		}

		_, err = nk.Seed()
		if err != nil {
			return err
		}

		return nil
	}
}

func LoadFromURL(url string) ([]byte, error) {
	c := &http.Client{Timeout: time.Second * 5}
	r, err := c.Get(url)
	if err != nil {
		return nil, fmt.Errorf("error loading %q: %v", url, err)
	}
	defer r.Body.Close()
	var buf bytes.Buffer
	_, err = io.Copy(&buf, r.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response from %q: %v", url, err)
	}
	data := buf.Bytes()
	return data, nil
}

func IsValidDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("not a directory")
	}
	return nil
}

func MaybeMakeDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil && os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("error creating %q: %v", dir, err)
		}
	} else if err != nil {
		return fmt.Errorf("error stat'ing %q: %v", dir, err)
	} else if !fi.IsDir() {
		return fmt.Errorf("%q already exists and it is not a dir", dir)
	}
	return nil
}

func AbbrevHomePaths(fp string) string {
	h, err := homedir.Dir()
	if err != nil {
		return fp
	}
	if strings.HasPrefix(fp, h) {
		return strings.Replace(fp, h, "~", 1)
	}
	return fp
}

func MaxArgs(max int) cobra.PositionalArgs {
	// if we are running in a test, remove the limit
	if strings.Contains(strings.Join(os.Args, " "), "-test.v") {
		return nil
	}
	return cobra.MaximumNArgs(max)
}

// ShortKey returns the first 12 characters of a public key (or the key if it is < 12 long)
func ShortCodes(s string) string {
	if WideFlag {
		return s
	}
	if s != "" && len(s) > 12 {
		s = s[0:12]
	}

	return s
}

// ExpandPath expands the specified path calls. Resolves ~/ and ./.. paths.
func Expand(s string) (string, error) {
	var err error
	s, err = homedir.Expand(s)
	if err != nil {
		return "", err
	}
	return filepath.Abs(s)
}
