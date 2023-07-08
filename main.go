// MIT License
//
// # Copyright (c) 2023 Jimmy Fjällid
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
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/term"
	rundebug "runtime/debug"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/dcerpc"
	"github.com/jfjallid/golog"
)

var log = golog.Get("")
var release string = "0.1"

func isFlagSet(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func printFiles(files []smb.SharedFile) {
	if len(files) > 0 {
		for _, file := range files {
			fileType := "file"
			if file.IsDir {
				fileType = "dir"
			} else if file.IsJunction {
				fileType = "link"
			}
			// Microsoft handles time as number of 100-nanosecond intervals since January 1, 1601 UTC
			// So to get a timestamp with unix time, subtract difference in 100-nanosecond intervals
			// and divide by 10 to convert to microseconds
			lastWriteTime := time.UnixMicro(int64((file.LastWriteTime - 116444736000000000) / 10))
			lastWrite := lastWriteTime.Format("Mon Jan 2 15:04:05 MST 2006")
			fmt.Printf("%-4s  %10d  %-30s  %s\n", fileType, file.Size, lastWrite, file.Name)
		}
	}
	fmt.Println()
}

func listFilesRecursively(session *smb.Connection, share, parent, dir string) error {
	parent = fmt.Sprintf("%s\\%s", share, parent)
	fmt.Printf("%s:\n", parent)
	files, err := session.ListDirectory(share, dir, "*")
	if err != nil {
		log.Errorf("Failed to list files in directory %s with error: %s\n", dir, err)
		fmt.Println()
		return nil
	}
	printFiles(files)
	for _, file := range files {
		if file.IsDir && !file.IsJunction {
			err = listFilesRecursively(session, share, file.FullPath, file.FullPath)
			if err != nil {
				log.Errorln(err)
				return err
			}
		}
	}
	return nil
}

func listFiles(session *smb.Connection, shares []string, recurse bool) error {
	for _, share := range shares {
		log.Noticef("Attempting to open share: %s and list content\n", share)
		// Connect to share
		err := session.TreeConnect(share)
		if err != nil {
			if err == smb.StatusMap[smb.StatusBadNetworkName] {
				fmt.Printf("Share %s can not be found!\n", share)
				continue
			}
			log.Errorln(err)
			continue
		}
		files, err := session.ListDirectory(share, "", "")
		if err != nil {

			if err == smb.StatusMap[smb.StatusAccessDenied] {
				session.TreeDisconnect(share)
				fmt.Printf("Could connect to [%s] but listing files was prohibited\n", share)
				continue
			}

			session.TreeDisconnect(share)
			log.Errorln(err)
			return err
		}

		fmt.Printf("\n#### Listing files for share (%s) ####\n", share)
		printFiles(files)
		if recurse {
			for _, file := range files {
				if file.IsDir && !file.IsJunction {
					err = listFilesRecursively(session, share, file.Name, file.FullPath)
					if err != nil {
						log.Errorln(err)
						session.TreeDisconnect(share)
						return err
					}
				}
			}
		}
		session.TreeDisconnect(share)
	}
	return nil
}

var helpMsg = `
    Usage: ` + os.Args[0] + ` [options]

    options:
          --host       Hostname or ip address of remote server
      -p, --port       SMB Port (default 445)
      -d, --domain     Domain name to use for login
      -u, --user       Username
      -P, --pass       Password
          --hash       Hex encoded NT Hash for user password
          --local      Authenticate as a local user instead of domain user
      -n, --null	   Attempt null session authentication
      -t, --timeout    Dial timeout in seconds (default 5)
          --enum       List available SMB shares
          --exclude    Comma-separated list of shares to exclude
          --list       Perform directory listing of shares
          --shares     Comma-separated list of shares to connect to
      -r, --recurse    Recursively list directories on server
          --noenc      Disable smb encryption
          --smb2       Force smb 2.1
          --debug      Enable debug logging
      -v, --version    Show version
`

func main() {
	var host, username, password, hash, domain, shareFlag, excludeShareFlag string
	var port, dialTimeout int
	var debug, dirList, recurse, shareEnumFlag, noEnc, forceSMB2, localUser, nullSession, version bool

	flag.Usage = func() {
		fmt.Println(helpMsg)
		os.Exit(0)
	}

	flag.StringVar(&host, "host", "", "")
	flag.StringVar(&username, "u", "", "")
	flag.StringVar(&username, "user", "", "")
	flag.StringVar(&password, "P", "", "")
	flag.StringVar(&password, "pass", "", "")
	flag.StringVar(&hash, "hash", "", "")
	flag.StringVar(&domain, "d", "", "")
	flag.StringVar(&domain, "domain", "", "")
	flag.IntVar(&port, "p", 445, "")
	flag.IntVar(&port, "port", 445, "")
	flag.BoolVar(&debug, "debug", false, "")
	flag.StringVar(&shareFlag, "shares", "", "")
	flag.BoolVar(&dirList, "list", false, "")
	flag.BoolVar(&recurse, "r", false, "")
	flag.BoolVar(&recurse, "recurse", false, "")
	flag.BoolVar(&shareEnumFlag, "enum", false, "")
	flag.StringVar(&excludeShareFlag, "exclude", "", "")
	flag.BoolVar(&noEnc, "noenc", false, "")
	flag.BoolVar(&forceSMB2, "smb2", false, "")
	flag.BoolVar(&localUser, "local", false, "")
	flag.IntVar(&dialTimeout, "t", 5, "")
	flag.IntVar(&dialTimeout, "timeout", 5, "")
	flag.BoolVar(&nullSession, "n", false, "")
	flag.BoolVar(&nullSession, "null", false, "")
	flag.BoolVar(&version, "v", false, "")
	flag.BoolVar(&version, "version", false, "")

	flag.Parse()

	if debug {
		golog.Set("github.com/jfjallid/go-smb/smb", "smb", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput)
		golog.Set("github.com/jfjallid/go-smb/gss", "gss", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput)
		log.SetFlags(golog.LstdFlags | golog.Lshortfile)
		log.SetLogLevel(golog.LevelDebug)
	} else {
		golog.Set("github.com/jfjallid/go-smb/smb", "smb", golog.LevelError, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput)
		golog.Set("github.com/jfjallid/go-smb/gss", "gss", golog.LevelError, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput)
	}

	if version {
		fmt.Printf("Version: %s\n", release)
		bi, ok := rundebug.ReadBuildInfo()
		if !ok {
			log.Errorln("Failed to read build info to locate version imported modules")
		}
		for _, m := range bi.Deps {
			fmt.Printf("Package: %s, Version: %s\n", m.Path, m.Version)
		}
		return
	}

	shares := []string{}
	netShares := []dcerpc.NetShare{}
	var hashBytes []byte
	var err error

	if host == "" {
		log.Errorln("Must specify a hostname")
		flag.Usage()
		return
	}

	if !shareEnumFlag {
		if shareFlag == "" {
			log.Errorln("Please specify a share name or the share enumeration flag.")
			return
		}
		shares = strings.Split(shareFlag, ",")

		if !dirList {
			log.Errorln("Please specify share enum flag or list flag!")
			return
		}
	}

	if dialTimeout < 1 {
		log.Errorln("Valid value for the timeout is > 0 seconds")
		return
	}

	if hash != "" {
		hashBytes, err = hex.DecodeString(hash)
		if err != nil {
			fmt.Println("Failed to decode hash")
			log.Errorln(err)
			return
		}
	}

	if (password == "") && (hashBytes == nil) {
		if (username != "") && (!nullSession) {
			// Check if password is already specified to be empty
			if !isFlagSet("P") && !isFlagSet("pass") {
				fmt.Printf("Enter password: ")
				passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
				fmt.Println()
				if err != nil {
					log.Errorln(err)
					return
				}
				password = string(passBytes)
			}
		}
	}

	// Put excluded shares in a map
	parts := strings.Split(excludeShareFlag, ",")
	excludedShares := make(map[string]bool)
	for _, part := range parts {
		excludedShares[part] = true
	}

	timeout, err := time.ParseDuration(fmt.Sprintf("%ds", dialTimeout))
	if err != nil {
		log.Errorln(err)
		return
	}
	options := smb.Options{
		Host: host,
		Port: port,
		Initiator: &smb.NTLMInitiator{
			User:               username,
			Password:           password,
			Hash:               hashBytes,
			Domain:             domain,
			LocalUser:          localUser,
			NullSession:        nullSession,
			EncryptionDisabled: noEnc,
		},
		DisableEncryption: noEnc,
		ForceSMB2:         forceSMB2,
		DialTimeout:       timeout,
	}
	session, err := smb.NewConnection(options)
	if err != nil {
		log.Criticalln(err)
		return
	}
	defer session.Close()

	if session.IsSigningRequired.Load() {
		log.Noticeln("[-] Signing is required")
	} else {
		log.Noticeln("[+] Signing is NOT required")
	}

	if session.IsAuthenticated {
		log.Noticeln("[+] Login successful")
	} else {
		log.Noticeln("[-] Login failed")
	}

	if shareEnumFlag {
		share := "IPC$"
		err := session.TreeConnect(share)
		if err != nil {
			log.Errorln(err)
			return
		}
		f, err := session.OpenFile(share, "srvsvc")
		if err != nil {
			log.Errorln(err)
			session.TreeDisconnect(share)
			return
		}

		bind, err := dcerpc.Bind(f, dcerpc.MSRPCUuidSrvSvc, 3, 0, dcerpc.MSRPCUuidNdr)
		if err != nil {
			log.Errorln("Failed to bind to service")
			log.Errorln(err)
			f.CloseFile()
			session.TreeDisconnect(share)
			return
		}
		log.Infoln("Successfully performed Bind to service")

		result, err := bind.NetShareEnumAll(host)
		if err != nil {
			log.Errorln(err)
			f.CloseFile()
			session.TreeDisconnect(share)
			return
		}

		// Replace list of shares when doing enumeration
		shares = []string{}
		for _, netshare := range result {
			name := netshare.Name[:len(netshare.Name)-1]
			if _, ok := excludedShares[name]; ok {
				// Exclude share
				continue
			}
			netShares = append(netShares, netshare)
			if netshare.TypeId == dcerpc.StypeDisktree {
				shares = append(shares, name)
			}
		}
		f.CloseFile()
		session.TreeDisconnect(share)

		log.Debugf("Retrieved list of %d shares\n", len(shares))

		fmt.Printf("\n#### %s ####\n", host)
		if dirList {
			err = listFiles(session, shares, recurse)
			if err != nil {
				log.Errorln(err)
				return
			}
		} else {
			fmt.Printf("\nShares:\n")
			for _, share := range netShares {
				fmt.Printf("Name: %s\nComment: %s\nHidden: %v\nType: %s\n\n", share.Name, share.Comment, share.Hidden, share.Type)
			}
		}
	} else {
		fmt.Printf("#### %s ####\n", host)
		// Use specified list of shares
		err = listFiles(session, shares, recurse)
		if err != nil {
			log.Errorln(err)
			return
		}
	}
}
