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
	"path/filepath"
	"sort"
	"strings"

	"github.com/nats-io/nkeys"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
	flag "github.com/spf13/pflag"
)

// addCmd represents the add command
var testCmd = &cobra.Command{
	Hidden: true,
	Use:    "test",
	Short:  "Test commands",
}

type GenerateNKeysParam struct {
	operator bool
	account  bool
	user     bool
	cluster  bool
	server   bool
}

func (p *GenerateNKeysParam) PrintKey(kind nkeys.PrefixByte, cmd *cobra.Command) {
	kp, err := nkeys.CreatePair(kind)
	if err != nil {
		panic(err)
	}
	seed, err := kp.Seed()
	if err != nil {
		panic(err)
	}

	cmd.Println(string(seed))

	pub, err := kp.PublicKey()
	if err != nil {
		panic(err)
	}
	cmd.Println(pub)
}

func (p *GenerateNKeysParam) Run(cmd *cobra.Command) error {
	if p.operator {
		p.PrintKey(nkeys.PrefixByteOperator, cmd)
	}
	if p.account {
		p.PrintKey(nkeys.PrefixByteAccount, cmd)
	}
	if p.user {
		p.PrintKey(nkeys.PrefixByteUser, cmd)
	}
	if p.cluster {
		p.PrintKey(nkeys.PrefixByteCluster, cmd)
	}
	if p.server {
		p.PrintKey(nkeys.PrefixByteServer, cmd)
	}
	return RunInterceptor(nil, nil)
}

func createGenerateNkey() *cobra.Command {
	var params GenerateNKeysParam
	cmd := &cobra.Command{
		Use:           "nkey",
		Short:         "Generates an nkey",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return params.Run(cmd)
		},
	}
	cmd.Flags().BoolVarP(&params.operator, "operator", "o", false, "operator")
	cmd.Flags().BoolVarP(&params.account, "account", "a", false, "account")
	cmd.Flags().BoolVarP(&params.user, "user", "u", false, "user")
	cmd.Flags().BoolVarP(&params.cluster, "cluster", "c", false, "cluster")
	cmd.Flags().BoolVarP(&params.server, "server", "s", false, "server")

	return cmd
}

func createFlagTable() *cobra.Command {
	var cmds flagTable
	cmd := &cobra.Command{
		Use:           "flags",
		Short:         "prints a table with all the flags",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {

			var buf Stack
			buf.Push(rootCmd)

			for {
				v := buf.Pop()
				if v == nil {
					break
				}
				if v.HasSubCommands() {
					for _, vv := range v.Commands() {
						buf.Push(vv)
					}
					continue
				} else {
					cmds.addCmd(v)
				}
			}
			return Write("--", []byte(cmds.render()))
		},
	}
	return cmd
}

func generateDoc() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "doc",
		Short: "generate markdown documentation in the specified directory",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := filepath.Abs(args[0])
			if err != nil {
				return err
			}
			if err = MaybeMakeDir(dir); err != nil {
				return err
			}
			return doc.GenMarkdownTree(rootCmd, dir)
		},
	}
	return cmd
}

type Stack struct {
	data []*cobra.Command
}

func (s *Stack) Push(v *cobra.Command) {
	s.data = append([]*cobra.Command{v}, s.data...)
}

func (s *Stack) Pop() *cobra.Command {
	var v *cobra.Command
	if len(s.data) == 0 {
		return nil
	}
	v = s.data[0]
	s.data = s.data[1:]
	return v
}

func reverse(a []string) {
	for i := len(a)/2 - 1; i >= 0; i-- {
		opp := len(a) - 1 - i
		a[i], a[opp] = a[opp], a[i]
	}
}

type parsedCommand struct {
	name    string
	flagMap map[string]string
}

type flagTable struct {
	commands []parsedCommand
}

func (t *flagTable) addCmd(cmd *cobra.Command) {
	var c parsedCommand
	c.flagMap = make(map[string]string)
	names := []string{cmd.Name()}
	v := cmd
	for {
		p := v.Parent()
		if p == nil {
			break
		}
		names = append(names, p.Name())
		v = p
	}
	reverse(names)
	c.name = strings.Join(names, " ")

	flags := cmd.Flags()
	flags.VisitAll(func(f *flag.Flag) {
		c.flagMap[f.Name] = f.Shorthand
	})

	t.commands = append(t.commands, c)
}

func (t *flagTable) render() string {
	var buf bytes.Buffer

	allFlags := make(map[string]bool)
	for _, c := range t.commands {
		for n := range c.flagMap {
			allFlags[n] = true
		}
	}
	var cols []string
	for k := range allFlags {
		cols = append(cols, k)
	}
	sort.Strings(cols)
	cols = append([]string{"cmd"}, cols...)

	buf.WriteString(strings.Join(cols, ","))
	buf.WriteString("\n")

	for _, c := range t.commands {
		sf := []string{c.name}
		for i := 1; i < len(cols); i++ {
			v, ok := c.flagMap[cols[i]]
			if v != "" {
				sf = append(sf, v)
			} else if ok {
				sf = append(sf, "-")
			} else {
				sf = append(sf, "")
			}
		}
		buf.WriteString(strings.Join(sf, ","))
		buf.WriteString("\n")
	}

	return buf.String()
}

func init() {
	GetRootCmd().AddCommand(testCmd)
	testCmd.AddCommand(createGenerateNkey())
	testCmd.AddCommand(createFlagTable())
	testCmd.AddCommand(generateDoc())
}
