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

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/dcerpc"
	"github.com/jfjallid/golog"
)

var log = golog.Get("")

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

func main() {
	host := flag.String("host", "", "host")
	username := flag.String("user", "", "username")
	password := flag.String("pass", "", "password")
	hash := flag.String("hash", "", "hex encoded NT Hash for user")
	domain := flag.String("d", "", "domain")
	port := flag.Int("port", 445, "SMB Port")
	debug := flag.Bool("debug", false, "enable debugging")
	shareFlag := flag.String("shares", "", "Comma-separated list of shares to connect to")
	dirList := flag.Bool("list", false, "Perform directory listing of shares")
	recurse := flag.Bool("recurse", false, "Recursively list directories on server")
	shareEnumFlag := flag.Bool("enum", false, "List available SMB shares")
	excludeShareFlag := flag.String("exclude", "", "Comma-separated list of shares to exclude")
	noEnc := flag.Bool("noenc", false, "disable smb encryption")
	forceSMB2 := flag.Bool("smb2", false, "Force smb 2.1")
	localUser := flag.Bool("local", false, "Authenticate as a local user instead of domain user")
	dialTimeout := flag.Int("timeout", 5, "Dial timeout in seconds")
	nullSession := flag.Bool("n", false, "Attempt null session authentication")

	flag.Parse()

	if *debug {
		golog.Set("github.com/jfjallid/go-smb/smb", "smb", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput)
		golog.Set("github.com/jfjallid/go-smb/gss", "gss", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput)
		log.SetFlags(golog.LstdFlags | golog.Lshortfile)
		log.SetLogLevel(golog.LevelDebug)
	} else {
		golog.Set("github.com/jfjallid/go-smb/smb", "smb", golog.LevelError, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput)
		golog.Set("github.com/jfjallid/go-smb/gss", "gss", golog.LevelError, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput)
	}

	shares := []string{}
	netShares := []dcerpc.NetShare{}
	var hashBytes []byte
	var err error

	if *host == "" {
		log.Errorln("Must specify a hostname")
		flag.Usage()
		return
	}

	if !*shareEnumFlag {
		if *shareFlag == "" {
			log.Errorln("Please specify a share name or the share enumeration flag.")
			return
		}
		shares = strings.Split(*shareFlag, ",")

		if !*dirList {
			log.Errorln("Please specify share enum flag or list flag!")
			return
		}
	}

	if *dialTimeout < 1 {
		log.Errorln("Valid value for the timeout is > 0 seconds")
		return
	}

	if *hash != "" {
		hashBytes, err = hex.DecodeString(*hash)
		if err != nil {
			fmt.Println("Failed to decode hash")
			log.Errorln(err)
			return
		}
	}

	if (*password == "") && (hashBytes == nil) && (*username != "") {
		fmt.Printf("Enter password: ")
		passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			log.Errorln(err)
			return
		}
		*password = string(passBytes)
	}

	// Put excluded shares in a map
	parts := strings.Split(*excludeShareFlag, ",")
	excludedShares := make(map[string]bool)
	for _, part := range parts {
		excludedShares[part] = true
	}

	timeout, err := time.ParseDuration(fmt.Sprintf("%ds", *dialTimeout))
	if err != nil {
		log.Errorln(err)
		return
	}
	options := smb.Options{
		Host: *host,
		Port: *port,
		Initiator: &smb.NTLMInitiator{
			User:               *username,
			Password:           *password,
			Hash:               hashBytes,
			Domain:             *domain,
			LocalUser:          *localUser,
			NullSession:        *nullSession,
			EncryptionDisabled: *noEnc,
		},
		DisableEncryption: *noEnc,
		//RequireMessageSigning: true,
		ForceSMB2:   *forceSMB2,
		DialTimeout: timeout,
	}
	session, err := smb.NewConnection(options)
	if err != nil {
		log.Criticalln(err)
		return
	}
	defer session.Close()

	if session.IsSigningRequired {
		log.Noticeln("[-] Signing is required")
	} else {
		log.Noticeln("[+] Signing is NOT required")
	}

	if session.IsAuthenticated {
		log.Noticeln("[+] Login successful")
	} else {
		log.Noticeln("[-] Login failed")
	}

	if *shareEnumFlag {
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

		result, err := bind.NetShareEnumAll(*host)
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

		fmt.Printf("\n#### %s ####\n", *host)
		if *dirList {
			err = listFiles(session, shares, *recurse)
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
		fmt.Printf("#### %s ####\n", *host)
		// Use specified list of shares
		err = listFiles(session, shares, *recurse)
		if err != nil {
			log.Errorln(err)
			return
		}
	}
}
