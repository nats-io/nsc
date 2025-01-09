// Copyright 2018-2025 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/mitchellh/go-homedir"
	cli "github.com/nats-io/cliprompts/v2"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/spf13/cobra"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/nats-io/nsc/v2/cmd/store"
)

// ResolvePath resolves a directory/file from an environment variable
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
			return nil, fmt.Errorf("error calculating abs %#q: %v", fp, err)
		}
		_, err = os.Stat(afp)
		if err == nil {
			return nil, fmt.Errorf("%#q already exists", afp)
		}
		if !os.IsNotExist(err) {
			return nil, err
		}

		f, err = os.Create(afp)
		if err != nil {
			return nil, fmt.Errorf("error creating output file %#q: %v", afp, err)
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

	parent := filepath.Dir(fp)
	if parent != "" {
		if err := os.MkdirAll(parent, 0700); err != nil {
			return fmt.Errorf("error creating dirs %#q: %v", fp, err)
		}
	}
	if err := os.WriteFile(fp, data, 0600); err != nil {
		return fmt.Errorf("error writing %#q: %v", fp, err)
	}

	return nil
}

func WriteFile(fp string, data []byte) error {
	return os.WriteFile(fp, data, 0600)
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
		return fmt.Errorf("error writing %#q: %v", fp, err)
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
	fp, err := Expand(fp)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(fp)
}

func ParseNumber(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	isNeg := strings.HasPrefix(s, "-")
	if isNeg {
		s = strings.TrimPrefix(s, "-")
	}
	i, err := humanize.ParseBytes(s)
	if err != nil {
		return 0, err
	}
	if isNeg {
		return -(int64)(i), nil
	}
	return (int64)(i), nil
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
		return strings.TrimSpace(TitleCase(humanize.RelTime(when, now, "ago", "")))
	} else {
		return strings.TrimSpace(TitleCase("in " + humanize.RelTime(now, when, "", "")))
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

func SeedNKeyValidatorMatching(pukeys []string, kinds ...nkeys.PrefixByte) cli.Validator {
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
		foundKind := false
		kindNames := []string{}
		for _, kind := range kinds {
			if t == kind {
				foundKind = true
				break
			}
			kindNames = append(kindNames, kind.String())
		}
		if !foundKind {
			return fmt.Errorf("specified key is not valid for any of %v", kindNames)
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

func IsURL(v string) bool {
	if u, err := url.Parse(v); err == nil {
		s := strings.ToLower(u.Scheme)
		return s == "http" || s == "https"
	}
	return false
}

func LoadFromFileOrURL(v string) ([]byte, error) {
	// we expect either a file or url
	if IsURL(v) {
		return LoadFromURL(v)
	}
	v, err := Expand(v)
	if err != nil {
		return nil, err
	}
	_, err = os.Stat(v)
	if err != nil {
		return nil, err
	}
	return Read(v)
}

func LoadFromURL(url string) ([]byte, error) {
	c := &http.Client{Timeout: time.Second * 5}
	r, err := c.Get(url)
	if err != nil {
		return nil, fmt.Errorf("error loading %q: %v", url, err)
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error reading response from %q: %v", url, r.Status)
	}
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
			return fmt.Errorf("error creating %#q: %v", dir, err)
		}
	} else if err != nil {
		return fmt.Errorf("error stat'ing %#q: %v", dir, err)
	} else if !fi.IsDir() {
		return fmt.Errorf("%#q already exists and it is not a dir", dir)
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

func NameFlagOrArgument(name string, ctx ActionCtx) string {
	return nameFlagOrArgument(name, ctx.Args())
}

func nameFlagOrArgument(name string, args []string) string {
	if name == "" && len(args) > 0 {
		return args[0]
	}
	return name
}

func MaxArgs(max int) cobra.PositionalArgs {
	// if we are running in a test, remove the limit
	if strings.Contains(strings.Join(os.Args, " "), "-test.v") {
		return nil
	}
	return cobra.MaximumNArgs(max)
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

func PushAccount(u string, accountjwt []byte) (int, []byte, error) {
	resp, err := http.Post(u, "application/text", bytes.NewReader(accountjwt))
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	return resp.StatusCode, data, err
}

func IsAccountAvailable(status int) bool {
	return status == http.StatusOK
}

func IsAccountPending(status int) bool {
	return status > http.StatusOK && status < 300
}

// Validate an operator name
func OperatorNameValidator(v string) error {
	operators := GetConfig().ListOperators()
	for _, o := range operators {
		if o == v {
			r := GetConfig().StoreRoot
			return fmt.Errorf("an operator named %#q already exists in %#q - specify a different directory with --dir", v, r)
		}
	}
	return nil
}

func AccountJwtURLFromString(asu string, accountSubject string) (string, error) {
	u, err := url.Parse(asu)
	if err != nil {
		return "", err
	}
	u.Path = path.Join(u.Path, "accounts", accountSubject)
	return u.String(), nil
}

func AccountJwtURL(oc *jwt.OperatorClaims, ac *jwt.AccountClaims) (string, error) {
	if oc.AccountServerURL == "" {
		return "", fmt.Errorf("error: operator %q doesn't set an account server url", oc.Name)
	}
	return AccountJwtURLFromString(oc.AccountServerURL, ac.Subject)
}

func OperatorJwtURLFromString(asu string) (string, error) {
	u, err := url.Parse(asu)
	if err != nil {
		return "", err
	}
	u.Path = path.Join(u.Path, "operator")
	return u.String(), nil
}

func OperatorJwtURL(oc *jwt.OperatorClaims) (string, error) {
	if oc.AccountServerURL == "" {
		return "", fmt.Errorf("error: operator %q doesn't set an account server url", oc.Name)
	}
	return OperatorJwtURLFromString(oc.AccountServerURL)
}

func IsNatsUrl(url string) bool {
	return store.IsNatsUrl(url)
}

func IsAccountServerURL(u string) bool {
	return store.IsAccountServerURL(u)
}

func IsResolverURL(u string) bool {
	return store.IsResolverURL(u)
}

func ValidSigner(kp nkeys.KeyPair, signers []string) (bool, error) {
	pk, err := kp.PublicKey()
	if err != nil {
		return false, err
	}
	ok := false
	for _, v := range signers {
		if pk == v {
			ok = true
			break
		}
	}
	return ok, nil
}

func GetOperatorSigners(ctx ActionCtx) ([]string, error) {
	oc, err := ctx.StoreCtx().Store.ReadOperatorClaim()
	if err != nil {
		return nil, err
	}
	var signers []string
	if !oc.StrictSigningKeyUsage {
		signers = append(signers, oc.Subject)
	}
	signers = append(signers, oc.SigningKeys...)
	return signers, nil
}

func diffDates(format string, a, b int64) store.Status {
	if a != b {
		as := "always"
		if a != 0 {
			as = UnixToDate(a)
		}
		bs := "always"
		if b != 0 {
			bs = UnixToDate(b)
		}
		v := fmt.Sprintf("from %s to %s", as, bs)
		return store.NewServerMessage(format, v)
	}
	return nil
}

func limitToString(v int64) string {
	switch v {
	case -1:
		return "unlimited"
	default:
		return fmt.Sprintf("%d", v)
	}
}

func diffNumber(format string, a, b int64) store.Status {
	if a != b {
		as := limitToString(a)
		bs := limitToString(b)
		v := fmt.Sprintf("from %s to %s", as, bs)
		return store.NewServerMessage(format, v)
	}
	return nil
}

func diffBool(format string, a, b bool) store.Status {
	if a != b {
		v := fmt.Sprintf("from %t to %t", a, b)
		return store.NewServerMessage(format, v)
	}
	return nil
}

func DiffAccountLimits(a *jwt.AccountClaims, b *jwt.AccountClaims) store.Status {
	r := store.NewReport(store.WARN, "account server modifications")
	r.Add(diffDates("jwt start changed %s", a.NotBefore, b.NotBefore))
	r.Add(diffDates("jwt expiry changed %s", a.NotBefore, b.NotBefore))
	r.Add(diffNumber("max subscriptions changed %s", a.Limits.Subs, b.Limits.Subs))
	r.Add(diffNumber("max connections changed %s", a.Limits.Conn, b.Limits.Conn))
	r.Add(diffNumber("max leaf node connections changed %s", a.Limits.LeafNodeConn, b.Limits.LeafNodeConn))
	r.Add(diffNumber("max imports changed %s", a.Limits.Imports, b.Limits.Imports))
	r.Add(diffNumber("max exports changed %s", a.Limits.Exports, b.Limits.Exports))
	r.Add(diffNumber("max data changed %s", a.Limits.Data, b.Limits.Data))
	r.Add(diffNumber("max message payload changed %s", a.Limits.Payload, b.Limits.Payload))
	r.Add(diffBool("allow wildcard exports changed %s", a.Limits.WildcardExports, b.Limits.WildcardExports))
	if len(r.Details) == 0 {
		return nil
	}
	return r
}

func StoreAccountAndUpdateStatus(ctx ActionCtx, token string, status *store.Report) {
	rs, err := ctx.StoreCtx().Store.StoreClaim([]byte(token))
	// the order of the messages benefits from adding the status first
	if rs != nil {
		status.Add(rs)
	}
	if err != nil {
		status.AddFromError(err)
	}
}

func promptDuration(label string, defaultValue time.Duration) (time.Duration, error) {
	value, err := cli.Prompt(label, defaultValue.String())
	if err != nil {
		return time.Duration(0), err
	}
	if value == "" {
		return time.Duration(0), nil
	}
	return time.ParseDuration(value)
}

type dateTime int64

func (t *dateTime) Set(val string) error {
	if strings.TrimSpace(val) == "0" {
		*t = 0
		return nil
	}
	if v, err := time.Parse(time.RFC3339, val); err == nil {
		*t = dateTime(v.Unix())
		return nil
	}
	num, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return fmt.Errorf("provided value %q is not a number nor parsable as RFC3339", val)
	}
	*t = dateTime(num)
	return nil
}

func (t *dateTime) String() string {
	v := time.Unix(int64(*t), 0)
	return v.Format(time.RFC3339)
}

func (t *dateTime) Type() string {
	return "date-time"
}

func Debug(label string, v interface{}) {
	d, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		panic(err)
	}
	fmt.Println(label, string(d))
}

var (
	englishCaser cases.Caser
	caserOnce    sync.Once
)

func TitleCase(s string) string {
	caserOnce.Do(func() {
		englishCaser = cases.Title(language.English)
	})
	return englishCaser.String(s)
}
