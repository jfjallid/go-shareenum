// MIT License
//
// # Copyright (c) 2026 Jimmy Fjällid
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/jfjallid/golog"
)

func readScriptFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var cmds []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cmds = append(cmds, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return cmds, nil
}

func splitInlineCommands(s string) []string {
	parts := strings.Split(s, ";")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// batchLoginRefusal returns a non-empty refusal message when a login-family
// command would otherwise drop into an interactive prompt (which is fatal in
// batch mode: term.ReadPassword fails on non-tty fds and self.t is nil so
// self.t.ReadLine would nil-deref).
func batchLoginRefusal(cmd string, args []string, host string) string {
	switch cmd {
	case "login", "login_hash":
		if len(args) < 2 {
			return fmt.Sprintf("%s in batch mode requires explicit credentials; refusing to prompt", cmd)
		}
	case "login_kerberos", "login_krb":
		if len(args) == 1 {
			return fmt.Sprintf("%s in batch mode requires either no args (ccache, hostname host) or <user/dom> <pass> [<spn>]; refusing to prompt for password", cmd)
		}
		if len(args) <= 2 && net.ParseIP(host) != nil {
			return fmt.Sprintf("%s in batch mode against an IP host requires an explicit SPN argument; refusing to prompt", cmd)
		}
	}
	return ""
}

func runBatchMode(opts *localOptions, inline, scriptPath string, debug, verbose bool) int {
	var cmds []string
	if scriptPath != "" {
		c, err := readScriptFile(scriptPath)
		if err != nil {
			log.Errorf("Failed to read script file %q: %v\n", scriptPath, err)
			return 1
		}
		cmds = c
	} else {
		cmds = splitInlineCommands(inline)
	}

	s := newShell(opts)
	if s == nil {
		return 1
	}
	s.batch = true

	if !debug && !verbose {
		// Silence the go-smb library loggers so scripted output stays clean.
		// golog.Names() enumerates every registered package logger; skip our
		// own "main" logger so connection/error notices still surface.
		for _, name := range golog.Names() {
			if name == "main" {
				continue
			}
			golog.Set(name, "", golog.LevelNone, 0, golog.NoOutput, golog.NoOutput)
		}
	}

	anyFailed := false
	for _, line := range cmds {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if line == "exit" {
			break
		}
		s.printf("# %s\n", line)

		cmd, rest, found := strings.Cut(line, " ")
		cmd = strings.ToLower(cmd)
		var args []string
		if found {
			args = parseArgs(rest)
		}

		s.cmdFailed = false

		if refusal := batchLoginRefusal(cmd, args, s.options.smbOptions.Host); refusal != "" {
			s.recordErrMsg(refusal)
			anyFailed = true
			continue
		}

		val, ok := handlers[cmd]
		if !ok {
			s.recordErrMsg("Unknown command: " + cmd)
			anyFailed = true
			continue
		}
		fn := val.(func(interface{}))

		func() {
			defer func() {
				if r := recover(); r != nil {
					s.recordErrf("panic in command %q: %v\n", cmd, r)
				}
			}()
			fn(args)
		}()

		if s.cmdFailed {
			anyFailed = true
		}
	}

	if anyFailed {
		return 1
	}
	return 0
}
