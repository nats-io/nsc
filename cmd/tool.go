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
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	nats "github.com/nats-io/nats.go"
	"github.com/spf13/cobra"
)

var toolCmd = &cobra.Command{
	Use:   "tool",
	Short: "NATS tools: pub, sub, req, rep, rtt",
}

var natsURLFlag = ""
var encryptFlag bool

func init() {
	toolCmd.PersistentFlags().StringVarP(&natsURLFlag, "nats", "", "", "nats url, defaults to the operator's service URLs")
	GetRootCmd().AddCommand(toolCmd)
}

func createDefaultToolOptions(name string, ctx ActionCtx) []nats.Option {
	connectTimeout := 5 * time.Second
	totalWait := 10 * time.Minute
	reconnectDelay := 2 * time.Second

	opts := []nats.Option{nats.Name(name)}
	opts = append(opts, nats.Timeout(connectTimeout))
	opts = append(opts, nats.ReconnectWait(reconnectDelay))
	opts = append(opts, nats.MaxReconnects(int(totalWait/reconnectDelay)))
	opts = append(opts, nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
		if err != nil {
			ctx.CurrentCmd().Printf("Disconnected: error: %v\n", err)
		}
		if nc.Status() == nats.CLOSED {
			return
		}
		ctx.CurrentCmd().Printf("Disconnected: will attempt reconnects for %.0fm", totalWait.Minutes())
	}))
	opts = append(opts, nats.ReconnectHandler(func(nc *nats.Conn) {
		ctx.CurrentCmd().Printf("Reconnected [%s]", nc.ConnectedUrl())
	}))
	opts = append(opts, nats.ClosedHandler(func(nc *nats.Conn) {
		if nc.Status() == nats.CLOSED {
			return
		}
		ctx.CurrentCmd().Printf("Exiting, no servers available, or connection closed")
	}))
	return opts
}

func createCypher(pk string) (cipher.AEAD, error) {
	// hash the provided private nkey into 32 bytes
	hash := sha256.Sum256([]byte(pk))
	c, err := aes.NewCipher(hash[:32])
	if err != nil {
		return nil, fmt.Errorf("unable to generate cypher: %v", err)
	}

	// create the symmetric key cipher
	return cipher.NewGCM(c)
}

func EncryptKV(pk string, data []byte) ([]byte, error) {
	// source data is <k><space><v>
	i := bytes.IndexByte(data, ' ')
	if i == -1 {
		k, err := Encrypt(pk, data)
		if err != nil {
			return nil, err
		}
		return k, nil
	}
	// kv pair
	k, err := Encrypt(pk, data[:i])
	if err != nil {
		return nil, err
	}
	v, err := Encrypt(pk, data[i+1:])
	if err != nil {
		return nil, err
	}
	return bytes.Join([][]byte{k, v}, []byte(" ")), nil
}

func Encrypt(pk string, data []byte) ([]byte, error) {
	g, err := createCypher(pk)
	if err != nil {
		return nil, err
	}
	// creates a byte array the size of the nonce required
	nonce := make([]byte, g.NonceSize())
	// seed the nonce with the same seed so that we have predictable encryption
	if _, err = io.ReadFull(strings.NewReader(pk), nonce); err != nil {
		return nil, fmt.Errorf("error generating random sequence: %v", err)
	}
	// encrypt the data
	raw := g.Seal(nonce, nonce, data, nil)

	// encode the data
	var codec = base64.StdEncoding.WithPadding(base64.NoPadding)
	buf := make([]byte, codec.EncodedLen(len(raw)))
	codec.Encode(buf, raw)
	return buf[:], nil
}

func Decrypt(pk string, data []byte) ([]byte, error) {
	// response payloads may be encrypted or may be lists of values separated by a space
	if bytes.IndexByte(data, ' ') != -1 {
		var decoded [][]byte
		for _, a := range bytes.Split(data, []byte(" ")) {
			d, err := decrypt(pk, a)
			if err != nil {
				return nil, err
			}
			decoded = append(decoded, d)
		}
		return bytes.Join(decoded, []byte(" ")), nil
	} else {
		return decrypt(pk, data)
	}
}

func decrypt(pk string, data []byte) ([]byte, error) {
	var codec = base64.StdEncoding.WithPadding(base64.NoPadding)
	raw := make([]byte, codec.DecodedLen(len(data)))
	n, err := codec.Decode(raw, data)
	if err != nil {
		if _, ok := err.(base64.CorruptInputError); ok {
			// possibly not encrypted - so just return what we got
			return data, nil
		}
		return nil, err
	}
	raw = raw[:n]

	g, err := createCypher(pk)
	if err != nil {
		return nil, err
	}
	nonceLen := g.NonceSize()
	if nonceLen > len(raw) {
		return nil, errors.New("unexpected data length")
	}
	nonce, cypher := raw[:nonceLen], raw[nonceLen:]
	return g.Open(nil, nonce, cypher, nil)
}
