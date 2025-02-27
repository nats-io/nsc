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
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	flag "github.com/spf13/pflag"

	cli "github.com/nats-io/cliprompts/v2"
	"github.com/nats-io/jwt/v2"
	jwt1 "github.com/nats-io/jwt/v2/v1compat"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/require"

	"github.com/nats-io/nsc/v2/cmd/store"
)

type TestStore struct {
	Dir       string
	KeysDir   string
	ConfigDir string
	StoreDir  string

	Store    *store.Store
	KeyStore store.KeyStore

	OperatorKey     nkeys.KeyPair
	OperatorKeyPath string

	Server  *server.Server
	ports   *server.Ports
	Clients []*nats.Conn
}

// Some globals must be reset
func ResetForTests() {
	config = ToolConfig{}
	ResetSharedFlags()
	wellKnownOperators = nil
}

func ResetSharedFlags() {
	KeyPathFlag = ""
	Json = false
	Raw = false
	JsonPath = ""
	AllDirFlag = ""
	ConfigDirFlag = ""
	DataDirFlag = ""
	KeysDirFlag = ""
	var buf Stack
	buf.Push(rootCmd)
	for {
		c := buf.Pop()
		if c == nil {
			break
		}
		if c.HasSubCommands() {
			for _, sub := range c.Commands() {
				buf.Push(sub)
			}
		}
		flags := c.Flags()
		flags.VisitAll(func(f *flag.Flag) {
			if f.Changed {
				_ = f.Value.Set(f.DefValue)
			}
		})
	}
}

func NewEmptyStore(t *testing.T) *TestStore {
	ResetForTests()
	// init runs early
	SetEnvOptions()
	var ts TestStore

	ts.Dir = MakeTempDir(t)
	err := MaybeMakeDir(ts.Dir)
	require.NoError(t, err)

	ts.ConfigDir, err = filepath.Abs(filepath.Join(ts.Dir, "config"))
	require.NoError(t, err)
	ts.StoreDir, err = filepath.Abs(filepath.Join(ts.Dir, "stores"))
	require.NoError(t, err)
	ts.KeysDir, err = filepath.Abs(filepath.Join(ts.Dir, "keys"))
	require.NoError(t, err)

	_, err = LoadOrInit(ts.ConfigDir, ts.StoreDir, ts.KeysDir)
	require.NoError(t, err)

	// debug the test that created the store
	_ = os.WriteFile(filepath.Join(ts.Dir, "test.txt"), []byte(t.Name()), 0700)

	err = ForceStoreRoot(t, ts.GetStoresRoot())
	require.NoError(t, err)

	err = os.Setenv(NscHomeEnv, ts.ConfigDir)
	require.NoError(t, err)

	err = os.Setenv(store.NKeysPathEnv, ts.KeysDir)
	require.NoError(t, err)

	return &ts
}

func NewTestStoreWithOperator(t *testing.T, operatorName string, key nkeys.KeyPair) *TestStore {
	ts := NewEmptyStore(t)
	ts.OperatorKey = key
	ForceOperator(t, operatorName)
	ts.AddOperatorWithKey(t, operatorName, key)
	return ts
}

func NewTestStoreWithOperatorJWT(t *testing.T, operator string) *TestStore {
	oc, err := jwt.DecodeOperatorClaims(operator)
	require.NoError(t, err)
	ts := NewTestStoreWithOperator(t, oc.Name, nil)
	ts.Store.StoreClaim([]byte(operator))
	return ts
}

func (ts *TestStore) Reload(t *testing.T) {
	s, err := store.LoadStore(ts.Store.Dir)
	require.NoError(t, err)
	if ts.Store == nil {
		ts.Store = s
	}
	ctx, err := ts.Store.GetContext()
	require.NoError(t, err, "getting context")

	ts.KeyStore = ctx.KeyStore

	GetConfig().SetDefaults()
}

func (ts *TestStore) AddOperator(t *testing.T, operatorName string) *store.Store {
	_, _, kp := CreateOperatorKey(t)
	return ts.AddOperatorWithKey(t, operatorName, kp)
}

func (ts *TestStore) AddOperatorWithKey(t *testing.T, operatorName string, operator nkeys.KeyPair) *store.Store {
	storeRoot := ts.GetStoresRoot()
	operatorRoot := filepath.Join(storeRoot, operatorName)
	err := os.MkdirAll(operatorRoot, 0700)
	require.NoError(t, err, "error creating %#q", operatorRoot)

	nkeysDir := filepath.Join(ts.Dir, "keys")
	_, err = os.Stat(nkeysDir)
	if err != nil && os.IsNotExist(err) {
		err = os.Mkdir(nkeysDir, 0700)
		require.NoError(t, err, "error creating %#q", nkeysDir)
	}
	require.NoError(t, err)

	store.KeyStorePath = nkeysDir

	var nk = &store.NamedKey{}
	nk.Name = operatorName
	nk.KP = operator

	s, err := store.CreateStore(operatorName, storeRoot, nk)
	require.NoError(t, err)
	ts.Store = s

	ctx, err := ts.Store.GetContext()
	require.NoError(t, err, "getting context")

	ts.KeyStore = ctx.KeyStore
	ts.OperatorKey = operator
	ts.OperatorKeyPath = ""
	if operator != nil {
		ts.OperatorKeyPath, err = ts.KeyStore.Store(operator)
		require.NoError(t, err, "store operator key")
	}

	ForceOperator(t, operatorName)

	return s
}

func (ts *TestStore) SwitchOperator(t *testing.T, operator string) {
	storeRoot := ts.GetStoresRoot()
	s, err := store.LoadStore(filepath.Join(storeRoot, operator))
	require.NoError(t, err)
	ts.Store = s

	ctx, err := ts.Store.GetContext()
	require.NoError(t, err, "getting context")
	ts.KeyStore = ctx.KeyStore

	oc, err := s.LoadRootClaim()
	require.NoError(t, err)

	kp, err := ts.KeyStore.GetKeyPair(oc.Subject)
	require.NoError(t, err)

	ts.OperatorKey = kp
	ts.OperatorKeyPath = ""
	if kp != nil {
		ts.OperatorKeyPath = ts.KeyStore.GetKeyPath(oc.Subject)
	}

	ForceOperator(t, operator)
}

func NewTestStore(t *testing.T, operatorName string) *TestStore {
	_, _, kp := CreateOperatorKey(t)
	return NewTestStoreWithOperator(t, operatorName, kp)
}

func TestStoreTree(t *testing.T) {
	ts := NewTestStore(t, "foo")
	ts.AddAccount(t, "bar")
	ts.AddAccount(t, "foo")

	v, err := store.LoadStore(filepath.Join(config.StoreRoot, config.Operator))
	require.NoError(t, err)
	require.NotNil(t, v)
}

func (ts *TestStore) Done(t *testing.T) {
	for _, nc := range ts.Clients {
		nc.Close()
	}
	if ts.Server != nil {
		ts.Server.Shutdown()
		ts.ports = nil
	}
	cli.ResetPromptLib()
	if t.Failed() {
		t.Log("test artifacts:", ts.Dir)
	} else {
		os.RemoveAll(ts.Dir)
	}
}

func (ts *TestStore) AddSubDir(t *testing.T, name ...string) string {
	name = append([]string{ts.Dir}, name...)
	dir := filepath.Join(name...)
	require.NoError(t, os.MkdirAll(dir, 0777))
	return dir
}

func (ts *TestStore) List(t *testing.T) {
	filepath.Walk(ts.Dir, func(path string, info fs.FileInfo, err error) error {
		t.Log(strings.TrimPrefix(path, ts.Dir))
		return nil
	})
}

func (ts *TestStore) GetStoresRoot() string {
	return ts.StoreDir
}

func (ts *TestStore) AddAccount(t *testing.T, accountName string) {
	if !ts.Store.Has(store.Accounts, accountName, store.JwtName(accountName)) {
		_, err := ExecuteCmd(CreateAddAccountCmd(), []string{"--name", accountName}...)
		require.NoError(t, err)
	}
}

func (ts *TestStore) AddAccountWithSigner(t *testing.T, accountName string, sk nkeys.KeyPair) {
	if !ts.Store.Has(store.Accounts, accountName, store.JwtName(accountName)) {
		seed, err := sk.Seed()
		require.NoError(t, err)
		_, err = ExecuteCmd(HoistRootFlags(CreateAddAccountCmd()), []string{"--name", accountName, "-K", string(seed)}...)
		require.NoError(t, err)
	}
}

func (ts *TestStore) AddUser(t *testing.T, accountName string, userName string) {
	ts.AddAccount(t, accountName)
	_, err := ExecuteCmd(CreateAddUserCmd(), []string{"--account", accountName, "--name", userName}...)
	require.NoError(t, err)
}

func (ts *TestStore) AddUserWithSigner(t *testing.T, accountName string, userName string, sk nkeys.KeyPair) {
	ts.AddAccount(t, accountName)
	seed, err := sk.Seed()
	require.NoError(t, err)
	_, err = ExecuteCmd(HoistRootFlags(CreateAddUserCmd()), []string{"--account", accountName, "--name", userName, "-K", string(seed)}...)
	require.NoError(t, err)
}

func (ts *TestStore) AddExport(t *testing.T, accountName string, kind jwt.ExportType, subject string, accountTokenPosition uint, public bool) {
	flags := []string{"--account", accountName, "--subject", subject}
	if !public {
		flags = append(flags, "--private")
	}
	if kind == jwt.Service {
		flags = append(flags, "--service")
	}
	if accountTokenPosition > 0 {
		flags = append(flags, "--account-token-position", strconv.Itoa(int(accountTokenPosition)))
	}

	ts.AddAccount(t, accountName)
	_, err := ExecuteCmd(createAddExportCmd(), flags...)
	require.NoError(t, err)
}

func (ts *TestStore) ImportRequiresToken(t *testing.T, srcAccount string, subject string) bool {
	ac, err := ts.Store.ReadAccountClaim(srcAccount)
	require.NoError(t, err)
	for _, ex := range ac.Exports {
		if string(ex.Subject) == subject {
			return ex.TokenReq
		}
	}
	return false
}

func (ts *TestStore) AddImport(t *testing.T, srcAccount string, kind jwt.ExportType, subject string, targetAccountName string) {
	flags := []string{"--account", targetAccountName}
	if kind == jwt.Service {
		flags = append(flags, "--service")
	}

	if ts.ImportRequiresToken(t, srcAccount, subject) {
		token := ts.GenerateActivation(t, srcAccount, subject, targetAccountName)
		f, err := os.CreateTemp(ts.Dir, "token")
		require.NoError(t, err)
		_, err = f.WriteString(token)
		require.NoError(t, err)
		require.NoError(t, f.Close())
		flags = append(flags, "--token", f.Name())
	} else {
		flags = append(flags, "--src-account", srcAccount, "--remote-subject", subject)
	}
	_, err := ExecuteCmd(createAddImportCmd(), flags...)
	require.NoError(t, err)
}

func (ts *TestStore) GenerateActivation(t *testing.T, srcAccount string, subject string, targetAccount string) string {
	tpub := ts.GetAccountPublicKey(t, targetAccount)
	ac, err := ts.Store.ReadAccountClaim(srcAccount)
	require.NoError(t, err)
	for _, i := range ac.Exports {
		if subject == string(i.Subject) {
			break
		}
	}

	flags := []string{"--account", srcAccount, "--target-account", tpub, "--subject", subject}
	out, err := ExecuteCmd(createGenerateActivationCmd(), flags...)
	require.NoError(t, err)
	token, err := jwt.ParseDecoratedJWT([]byte(out.Out))
	require.NoError(t, err)
	return token
}

func (ts *TestStore) GenerateActivationWithSigner(t *testing.T, srcAccount string, subject string, targetAccount string, sk nkeys.KeyPair) string {
	tpub := ts.GetAccountPublicKey(t, targetAccount)
	seed, err := sk.Seed()
	require.NoError(t, err)

	flags := []string{"--account", srcAccount, "--target-account", tpub, "--subject", subject, "-K", string(seed)}
	out, err := ExecuteCmd(HoistRootFlags(createGenerateActivationCmd()), flags...)
	require.NoError(t, err)
	token, err := jwt.ParseDecoratedJWT([]byte(out.Out))
	require.NoError(t, err)
	return token
}

func MakeTempDir(t *testing.T) string {
	p, err := os.MkdirTemp("", "nsc_test")
	require.NoError(t, err)
	return p
}

func StoreKey(t *testing.T, kp nkeys.KeyPair, dir string) string {
	p, err := kp.PublicKey()
	require.NoError(t, err)

	s, err := kp.Seed()
	require.NoError(t, err)

	fp := filepath.Join(dir, string(p)+".nk")
	err = os.WriteFile(fp, s, 0600)
	require.NoError(t, err)
	return fp
}

func CreateAccountKey(t *testing.T) (seed []byte, pub string, kp nkeys.KeyPair) {
	return CreateNkey(t, nkeys.PrefixByteAccount)
}

func CreateUserKey(t *testing.T) (seed []byte, pub string, kp nkeys.KeyPair) {
	return CreateNkey(t, nkeys.PrefixByteUser)
}

func CreateOperatorKey(t *testing.T) (seed []byte, pub string, kp nkeys.KeyPair) {
	return CreateNkey(t, nkeys.PrefixByteOperator)
}

func CreateCurveKey(t *testing.T) (seed []byte, pub string, kp nkeys.KeyPair) {
	return CreateNkey(t, nkeys.PrefixByteCurve)
}

func CreateNkey(t *testing.T, kind nkeys.PrefixByte) ([]byte, string, nkeys.KeyPair) {
	kp, err := nkeys.CreatePair(kind)
	require.NoError(t, err)

	seed, err := kp.Seed()
	require.NoError(t, err)

	pub, err := kp.PublicKey()
	require.NoError(t, err)
	return seed, pub, kp
}

func ForceStoreRoot(t *testing.T, fp string) error {
	config.StoreRoot = fp
	return nil
}

func ForceOperator(t *testing.T, operator string) {
	config.Operator = operator
}

func StripTableDecorations(s string) string {
	decorations := []string{"╭", "─", "┬", "╮", "├", "│", "┤", "┼", "╰", "┴", "╯", "-", "+", "|"}
	for _, c := range decorations {
		s = strings.Replace(s, c, "", -1)
	}
	// replace multiple spaces with just one
	re := regexp.MustCompile(`\s+`)
	return re.ReplaceAllString(s, " ")
}

func StripMultipleSpaces(s string) string {
	re := regexp.MustCompile(` +`)
	return re.ReplaceAllString(s, " ")
}

func (ts *TestStore) GetAccountKey(t *testing.T, name string) nkeys.KeyPair {
	ac, err := ts.Store.ReadAccountClaim(name)
	require.NoError(t, err)
	kp, err := ts.KeyStore.GetKeyPair(ac.Subject)
	require.NoError(t, err)
	return kp
}

func (ts *TestStore) GetUserKey(t *testing.T, account string, name string) nkeys.KeyPair {
	uc, err := ts.Store.ReadUserClaim(account, name)
	require.NoError(t, err)
	kp, err := ts.KeyStore.GetKeyPair(uc.Subject)
	require.NoError(t, err)
	return kp
}

func (ts *TestStore) GetAccountKeyPath(t *testing.T, name string) string {
	sc, err := ts.Store.ReadAccountClaim(name)
	require.NoError(t, err)
	return ts.KeyStore.GetKeyPath(sc.Subject)
}

func (ts *TestStore) GetOperatorPublicKey(t *testing.T) string {
	oc, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	pk, err := ts.KeyStore.GetPublicKey(oc.Subject)
	require.NoError(t, err)
	return pk
}

func (ts *TestStore) GetAccountPublicKey(t *testing.T, name string) string {
	sc, err := ts.Store.ReadAccountClaim(name)
	require.NoError(t, err)
	pk, err := ts.KeyStore.GetPublicKey(sc.Subject)
	require.NoError(t, err)
	return pk
}

func (ts *TestStore) GetUserPublicKey(t *testing.T, account string, name string) string {
	sc, err := ts.Store.ReadUserClaim(account, name)
	require.NoError(t, err)
	pk, err := ts.KeyStore.GetPublicKey(sc.Subject)
	require.NoError(t, err)
	return pk
}

func (ts *TestStore) GetUserSeedKey(t *testing.T, account string, name string) string {
	sc, err := ts.Store.ReadUserClaim(account, name)
	require.NoError(t, err)
	pk, err := ts.KeyStore.GetSeed(sc.Subject)
	require.NoError(t, err)
	return pk
}

// Runs a server from a config file, if `Port` is not set it runs at a random port
func (ts *TestStore) RunServerWithConfig(t *testing.T, config string) *server.Ports {
	var opts server.Options
	require.NoError(t, opts.ProcessConfigFile(config))
	return ts.RunServer(t, &opts)
}

// Runs a NATS server at a random port
func (ts *TestStore) RunServer(t *testing.T, opts *server.Options) *server.Ports {
	if opts == nil {
		opts = &server.Options{
			Host:           "127.0.0.1",
			Port:           -1,
			HTTPPort:       -1,
			NoLog:          true,
			NoSigs:         true,
			MaxControlLine: 2048,
		}
	}
	if opts.Port == 0 {
		opts.Port = -1
	}
	if opts.HTTPPort == 0 {
		opts.HTTPPort = -1
	}
	opts.NoLog = true

	var err error
	ts.Server, err = server.NewServer(opts)
	require.NoError(t, err)
	require.NotNil(t, ts.Server)

	if !opts.NoLog {
		ts.Server.ConfigureLogger()
	}

	// Run server in Go routine.
	go ts.Server.Start()

	ts.ports = ts.Server.PortsInfo(10 * time.Second)
	require.NotNil(t, ts.ports)

	return ts.ports
}

func (ts *TestStore) GetConnz(t *testing.T) *server.Connz {
	if ts.ports == nil {
		t.Fatal("not connected")
	}
	r, err := http.Get(fmt.Sprintf("%s/connz", ts.ports.Monitoring[0]))
	require.NoError(t, err)

	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	require.NoError(t, err)

	var connz server.Connz
	require.NoError(t, json.Unmarshal(body, &connz))

	return &connz
}

func (ts *TestStore) CreateClient(t *testing.T, option ...nats.Option) *nats.Conn {
	if ts.ports == nil {
		t.Fatal("attempt to create a nats connection without a server running")
	}
	nc, err := nats.Connect(strings.Join(ts.ports.Nats, ","), option...)
	require.NoError(t, err)
	ts.Clients = append(ts.Clients, nc)
	return nc
}

func (ts *TestStore) WaitForClient(t *testing.T, name string, subs uint32, maxWait time.Duration) {
	max := time.Now().Add(maxWait)
	end := max.Unix()
	for {
		connz := ts.GetConnz(t)
		if connz.NumConns > 0 {
			for _, v := range connz.Conns {
				if v.Name == name && v.NumSubs >= subs {
					return
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
		if time.Now().Unix() >= end {
			t.Fatalf("timed out looking for client %q with %d subs", name, subs)
		}
	}
}

func (ts *TestStore) VerifyOperator(t *testing.T, name string, managed bool) {
	s, err := store.LoadStore(filepath.Join(ts.GetStoresRoot(), name))
	require.NoError(t, err)
	require.NotNil(t, s)

	oc, err := s.ReadOperatorClaim()
	require.NoError(t, err)
	require.NotNil(t, oc)
	require.Equal(t, name, oc.Name)
	require.Equal(t, managed, s.IsManaged())

	kp, err := ts.KeyStore.GetKeyPair(oc.Subject)
	require.NoError(t, err)
	if managed {
		require.Nil(t, kp)
	} else {
		require.NotNil(t, kp)
	}
}

func (ts *TestStore) VerifyAccount(t *testing.T, operator string, account string, verifyKeys bool) {
	s, err := store.LoadStore(filepath.Join(ts.GetStoresRoot(), operator))
	require.NoError(t, err)
	require.NotNil(t, s)

	ac, err := s.ReadAccountClaim(account)
	require.NoError(t, err)
	require.NotNil(t, ac)
	require.Equal(t, account, ac.Name)

	if verifyKeys {
		old := ts.KeyStore.Env
		defer func() {
			ts.KeyStore.Env = old
		}()
		ts.KeyStore.Env = operator

		kp, err := ts.KeyStore.GetKeyPair(ac.Subject)
		require.NoError(t, err)
		require.NotNil(t, kp)
	}
}

func (ts *TestStore) VerifyUser(t *testing.T, operator string, account string, user string, verifyKeys bool) {
	s, err := store.LoadStore(filepath.Join(ts.GetStoresRoot(), operator))
	require.NoError(t, err)
	require.NotNil(t, s)

	uc, err := s.ReadUserClaim(account, user)
	require.NoError(t, err)
	require.NotNil(t, uc)
	require.Equal(t, user, uc.Name)

	if verifyKeys {
		old := ts.KeyStore.Env
		defer func() {
			ts.KeyStore.Env = old
		}()
		ts.KeyStore.Env = operator

		kp, err := ts.KeyStore.GetKeyPair(uc.Subject)
		require.NoError(t, err)
		require.NotNil(t, kp)
		sk, err := kp.Seed()
		require.NoError(t, err)

		fp := ts.KeyStore.CalcUserCredsPath(account, user)
		_, err = os.Stat(fp)
		require.NoError(t, err)

		creds, err := Read(fp)
		require.NoError(t, err)
		require.Contains(t, string(creds), string(sk))
	}
}

func (ts *TestStore) DoesNotExist(t *testing.T, fp string) {
	_, err := os.Stat(fp)
	require.True(t, os.IsNotExist(err), fmt.Sprintf("should not exist %s", fp))
}

func Test_Util(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	oc, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	pk, _ := ts.OperatorKey.PublicKey()
	require.Equal(t, pk, oc.Subject)

	ts.AddAccount(t, "A")
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Equal(t, oc.Subject, ac.Issuer)

	_, pk, kp := CreateOperatorKey(t)
	ts.AddOperatorWithKey(t, "OO", kp)
	oc2, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	require.Equal(t, pk, oc2.Subject)

	ts.AddAccount(t, "AA")
	ac2, err := ts.Store.ReadAccountClaim("AA")
	require.NoError(t, err)
	require.Equal(t, pk, ac2.Issuer)
}

type TasOpts struct {
	Vers             int
	OperatorOnlyIfV2 bool
}

func RunTestAccountServerWithOperatorKP(t *testing.T, okp nkeys.KeyPair, opts TasOpts) (*httptest.Server, map[string][]byte) {
	storage := make(map[string][]byte)
	opk, err := okp.PublicKey()
	require.NoError(t, err)

	tas := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		errHandler := func(w http.ResponseWriter, err error) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
		}
		getHandler := func(w http.ResponseWriter, r *http.Request) {
			var data []byte
			id := filepath.Base(r.RequestURI)
			data = storage[id]

			// if we don't have v2, and they ask for v2, ignore it
			if r.RequestURI == "/jwt/v2/operator" && !opts.OperatorOnlyIfV2 {
				data = nil
			}
			if r.RequestURI == "/jwt/v1/operator" && opts.OperatorOnlyIfV2 {
				// option to only answer to v2 - they asked v1
				data = nil
			}

			if data == nil {
				w.WriteHeader(http.StatusNotFound)
			}
			w.Header().Add("Content-Type", "application/jwt")
			w.Write(data)
			if data == nil {
				t.Log(r.RequestURI, "not found")
			} else {
				t.Log(r.RequestURI, "OK")
			}
		}

		updateAccountHandler := func(w http.ResponseWriter, r *http.Request) {
			defer r.Body.Close()
			body, err := io.ReadAll(r.Body)
			if err != nil {
				errHandler(w, err)
				return
			}

			ac, err := jwt.DecodeAccountClaims(string(body))
			if err != nil {
				errHandler(w, err)
				return
			}

			ok := false
			if ac.Claims().IsSelfSigned() || ac.Issuer == opk {
				ok = true
			} else {
				ok = ac.SigningKeys.Contains(ac.Issuer)
			}

			// store a copy of the source jwt that we can inspect
			orig := fmt.Sprintf("SRC_%s", ac.Subject)
			storage[orig] = body

			if ok {
				ac.Limits.Conn = -1
				ac.Limits.Data = -1
				ac.Limits.Exports = -1
				ac.Limits.Imports = -1
				ac.Limits.LeafNodeConn = -1
				ac.Limits.Payload = -1
				ac.Limits.Subs = -1
				ac.Limits.WildcardExports = true

				token, err := ac.Encode(okp)
				if err != nil {
					errHandler(w, err)
					return
				}
				storage[ac.Subject] = []byte(token)

				w.WriteHeader(http.StatusOK)
			} else {
				errHandler(w, fmt.Errorf("account %q not self-signed nor by a signer - issuer %q", ac.Subject, ac.Issuer))
			}
		}

		updateActivationHandler := func(w http.ResponseWriter, r *http.Request) {
			defer r.Body.Close()
			body, err := io.ReadAll(r.Body)
			if err != nil {
				errHandler(w, err)
				return
			}

			ac, err := jwt.DecodeActivationClaims(string(body))
			if err != nil {
				errHandler(w, err)
				return
			}
			hid, err := ac.HashID()
			if err != nil {
				errHandler(w, err)
				return
			}
			storage[hid] = body
			w.WriteHeader(http.StatusOK)
		}

		switch r.Method {
		case http.MethodGet:
			getHandler(w, r)
		case http.MethodPost:
			p := r.URL.Path
			if strings.Contains(p, "/accounts/") {
				updateAccountHandler(w, r)
			} else if strings.HasSuffix(p, "/activations") {
				updateActivationHandler(w, r)
			}
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))

	if opts.Vers == 1 {
		oc := jwt1.NewOperatorClaims(opk)
		oc.Name = "T"
		oc.Subject = opk
		u, err := url.Parse(tas.URL)
		require.NoError(t, err)
		u.Path = "jwt/v1"
		oc.AccountServerURL = u.String()
		token, err := oc.Encode(okp)
		require.NoError(t, err)
		storage["operator"] = []byte(token)
	} else {
		oc := jwt.NewOperatorClaims(opk)
		oc.Name = "T"
		oc.Subject = opk
		u, err := url.Parse(tas.URL)
		require.NoError(t, err)
		u.Path = "jwt/v1"
		oc.AccountServerURL = u.String()
		token, err := oc.Encode(okp)
		require.NoError(t, err)
		storage["operator"] = []byte(token)
	}

	return tas, storage
}

// Runs a TestAccountServer returning the server and the underlying storage
func RunTestAccountServer(t *testing.T) (*httptest.Server, map[string][]byte) {
	_, _, okp := CreateOperatorKey(t)
	return RunTestAccountServerWithOperatorKP(t, okp, TasOpts{Vers: 2})
}

// EqualsPaths resolves any symlinks that may have been present
// ie /private/var vs /var in the paths
func EqualPaths(t *testing.T, a, b string) {
	var err error
	a, err = filepath.EvalSymlinks(a)
	require.NoError(t, err)
	b, err = filepath.EvalSymlinks(b)
	require.NoError(t, err)

	require.Equal(t, a, b)
}
