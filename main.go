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
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	rundebug "runtime/debug"

	"golang.org/x/net/proxy"
	"golang.org/x/term"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/dcerpc/mssrvs"
	"github.com/jfjallid/go-smb/dcerpc/smbtransport"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/spnego"
	"github.com/jfjallid/golog"
)

var log = golog.Get("")
var release string = "0.3.0"
var includedExts map[string]interface{}
var excludedExts map[string]interface{}
var excludedFolders map[string]interface{}
var nameRegexp *regexp.Regexp
var fileSizeThreshold uint64
var downloadDir string
var download bool

func isFlagSet(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func printFilesExt(files []smb.SharedFile) {
	if len(files) > 0 {
		for _, file := range files {
			fileType := "file"
			if file.IsDir {
				fileType = "dir"
			} else if file.IsJunction {
				fileType = "link"
			}
			if (fileType == "file") && (file.Size < fileSizeThreshold) {
				// Skip displaying file
				continue
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

func filterFiles(input []smb.SharedFile) []smb.SharedFile {
	files := make([]smb.SharedFile, 0)
	if len(input) > 0 {
		for _, file := range input {
			if file.IsDir || file.IsJunction {
				files = append(files, file)
				continue
			}
			// Check file extension
			fileExt := strings.TrimPrefix(path.Ext(file.Name), ".")
			if includedExts != nil {
				if _, ok := includedExts[fileExt]; !ok {
					// Skip file
					continue
				}
			} else if excludedExts != nil {
				if _, ok := excludedExts[fileExt]; ok {
					// Skip file
					continue
				}
			}

			// Check name regexp
			if nameRegexp != nil {
				if !nameRegexp.MatchString(file.Name) {
					// Skip file
					continue
				}
			}

			// File was either include by extension and regexp
			// or not explicitly excluded so keep it in the result
			files = append(files, file)
		}
	}

	return files
}

func getShares(options *localOptions, host string) (shares []string, err error) {
	share := "IPC$"
	err = options.c.TreeConnect(share)
	if err != nil {
		return
	}
	f, err := options.c.OpenFile(share, "srvsvc")
	if err != nil {
		options.c.TreeDisconnect(share)
		return
	}
	transport, err := smbtransport.NewSMBTransport(f)
	if err != nil {
		log.Errorln(err)
		return
	}

	bind, err := dcerpc.Bind(transport, mssrvs.MSRPCUuidSrvSvc, 3, 0, dcerpc.MSRPCUuidNdr)
	if err != nil {
		if !options.interactive {
			log.Errorln("Failed to bind to service")
		}
		f.CloseFile()
		options.c.TreeDisconnect(share)
		return
	}
	rpccon := mssrvs.NewRPCCon(bind)
	if !options.interactive {
		log.Infoln("Successfully performed Bind to service")
	}

	result, err := rpccon.NetShareEnumAll(host)
	if err != nil {
		f.CloseFile()
		options.c.TreeDisconnect(share)
		return
	}

	for _, netshare := range result {
		name := netshare.Name
		if (netshare.TypeId == mssrvs.StypeDisktree) || (netshare.TypeId == mssrvs.StypeIPC) {
			shares = append(shares, name)
		}
	}
	f.CloseFile()
	options.c.TreeDisconnect(share)

	return
}

func listShares(options *localOptions, host string) {
	shares, err := getShares(options, host)
	if err != nil {
		log.Errorln(err)
		return
	}
	log.Debugf("Retrieved list of %d shares\n", len(shares))
	for _, share := range shares {
		fmt.Println(share)
	}
}

func downloadFiles(session *smb.Connection, share string, files []smb.SharedFile, createDirectories bool) {
	if len(files) > 0 {
		for _, file := range files {
			if file.IsDir || file.IsJunction {
				// Skip
				continue
			}

			if file.Size < fileSizeThreshold {
				// Skip downloading file
				continue
			}
			// Determine full relative file path
			cleanedPath := path.Clean(file.FullPath)
			if path.IsAbs(cleanedPath) {
				// Could this be bypassed to escape to an absolute path?
				cleanedPath = strings.TrimPrefix(cleanedPath, string(os.PathSeparator))
			}

			if os.PathSeparator == '\\' {
				cleanedPath = strings.ReplaceAll(cleanedPath, "/", "\\")
			} else {
				cleanedPath = strings.ReplaceAll(cleanedPath, "\\", "/")
			}
			/* This does not work properly if the separator in the cleanedPath
			 * differs from the os specific path separator e.g., if the windows
			 * path is share\dir1\file and the client os is linux with a default
			 * path separator of /, then the Split function will fail to split
			 * the filename from the path.
			 */
			dir, filename := path.Split(cleanedPath)

			// Create sub folders if they do not already exist
			fulldir := ""
			if dir != "" {
				fulldir = downloadDir + string(os.PathSeparator) + strings.TrimSuffix(dir, string(os.PathSeparator))
			} else {
				fulldir = downloadDir
			}

			localFile := filename
			if createDirectories {
				err := os.MkdirAll(fulldir, 0755)
				if err != nil {
					log.Errorf("Failed to create dir %s with error: %v\n", fulldir, err)
					continue
				}
				localFile = fulldir + string(os.PathSeparator) + filename
			}

			// Open local file in the subdir and start downloading the file
			f, err := os.OpenFile(localFile, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0640)
			if err != nil {
				log.Errorln(err)
				continue
			}

			// Call library function to retrieve the file
			err = session.RetrieveFile(share, file.FullPath, 0, f.Write)
			if err != nil {
				log.Errorln(err)
				f.Close()
				continue
			}
			f.Close()
		}
	}
}

func listFilesRecursively(session *smb.Connection, share, parent, dir string, followJunctions bool) error {
	parent = fmt.Sprintf("%s\\%s", share, parent)
	fmt.Printf("Listing files in dir: %s\n", dir)
	files, err := session.ListDirectory(share, dir, "*")
	if err != nil {
		log.Infof("Failed to list files in directory (%s) with error: %s\n", dir, err)
		return nil
	}

	// Remove filtered files
	files = filterFiles(files)
	if len(files) == 0 {
		return nil
	}

	fmt.Printf("%s:\n", parent)
	printFilesExt(files)
	if download {
		downloadFiles(session, share, files, true)
	}

	for _, file := range files {
		if file.IsDir && (!file.IsJunction || followJunctions) {
			// Check if folder is filtered
			if _, ok := excludedFolders[file.Name]; ok {
				// Skip recursing into folder
				continue
			}
			err = listFilesRecursively(session, share, file.FullPath, file.FullPath, followJunctions)
			if err != nil {
				log.Errorln(err)
				return err
			}
		}
	}
	return nil
}

func listFiles(session *smb.Connection, shares []string, recurse, followJunctions bool, startDir string) error {
	for _, share := range shares {
		// Normalize: forward slashes to backslashes, strip leading/trailing separators
		dir := strings.ReplaceAll(startDir, "/", `\`)
		dir = strings.Trim(dir, `\`)

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
		files, err := session.ListDirectory(share, dir, "")
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

		// Remove filtered files
		files = filterFiles(files)

		if dir != "" {
			fmt.Printf("\n#### Listing files for share (%s\\%s) ####\n", share, dir)
		} else {
			fmt.Printf("\n#### Listing files for share (%s) ####\n", share)
		}
		printFilesExt(files)
		if download {
			downloadFiles(session, share, files, true)
		}
		if recurse {
			log.Debugf("recursion over files [%+v]\n", files)
			for _, file := range files {
				log.Debugf("Checking file: %+v\n", file)
				if file.IsDir && (!file.IsJunction || followJunctions) {
					// Check if folder is filtered
					if _, ok := excludedFolders[file.Name]; ok {
						// Skip recursing into folder
						continue
					}
					err = listFilesRecursively(session, share, file.Name, file.FullPath, followJunctions)
					if err != nil {
						log.Errorln(err)
						session.TreeDisconnect(share)
						return err
					}
				}
			}
		} else {
			fmt.Println("No recursion specified!")
		}
		session.TreeDisconnect(share)
	}
	return nil
}

func uploadFile(conn *smb.Connection, share, localFile, remotePath string, replaceFile bool) (err error) {
	var f *os.File
	filename := filepath.Base(localFile)
	if filename == "." || filename == string(os.PathSeparator) {
		err = fmt.Errorf("Could not determine filename for local file")
		return
	}

	// Remote paths should use Windows path separators
	remotePath = strings.ReplaceAll(remotePath, "/", "\\")

	if remotePath == "" {
		err = fmt.Errorf("remote path must not be empty")
		return
	}

	// Check if remotePath specifies filename
	if remotePath[len(remotePath)-1] == '\\' {
		remotePath += "\\" + filename
	}
	var modifiedRemoteFile string
	modifiedRemoteFile = remotePath

	if remotePath[0] == '\\' {
		modifiedRemoteFile = remotePath[1:] // Skip initial slash
	}

	// Check that local file exists
	f, err = os.Open(localFile)
	if err != nil {
		if os.IsNotExist(err) {
			log.Errorf("The local filename(%s) does not exist\n", localFile)
			return
		}
		log.Errorln(err)
		return
	}
	defer f.Close()

	log.Infof("Trying to upload the local file %s to share: %s, path: %s\n", localFile, share, modifiedRemoteFile)
	// Check if remote file exists
	createOpts := smb.NewCreateReqOpts()
	createOpts.CreateDisp = smb.FileCreate
	f2, err := conn.OpenFileExt(share, modifiedRemoteFile, createOpts)
	if err != nil {
		// Check if file exists and we want to replace it
		if err == smb.StatusMap[smb.StatusObjectNameCollision] {
			if !replaceFile {
				log.Errorf("The remote file %q already exists. Run with --replace to overwrite it\n", modifiedRemoteFile)
				return
			}
		} else {
			log.Errorln(err)
			return
		}
	} else {
		f2.CloseFile()
	}

	err = conn.PutFile(share, modifiedRemoteFile, 0, f.Read)
	if err != nil {
		log.Errorln(err)
		return
	}
	return nil
}

var helpMsg = `
    Usage: ` + os.Args[0] + ` [options]

    options:
          --host <target>          Hostname or ip address of remote server. Must be hostname when using Kerberos
      -P, --port <int>             SMB Port (default 445)
      -d, --domain <name/fqdn>     Domain name to use for login
      -u, --user <string>          Username
      -p, --pass <string>          Password
      -n, --no-pass                Disable password prompt and send no credentials
      -i, --interactive            Start an interactive session
          --hash <NT Hash>         Hex encoded NT Hash for user password
          --local                  Authenticate as a local user instead of domain user
          --null                   Attempt null session authentication
      -k, --kerberos               Use Kerberos authentication. (KRB5CCNAME will be checked on Linux)
          --dc-ip <ip>             Optionally specify ip of KDC when using Kerberos authentication
          --target-ip <ip>         Optionally specify ip of target when using Kerberos authentication
          --dns-host <ip:port>     Override system's default DNS resolver 
          --dns-tcp                Force DNS lookups over TCP. Default true when using --socks-host
          --aes-key <hex>          Use a hex encoded AES128/256 key for Kerberos authentication
      -t, --timeout <duration>     Dial timeout specified in 5s, 1m, 10m format (default 5s)
          --enum                   List available SMB shares
          --exclude <list>         Comma-separated list of shares to exclude
          --list                   Perform directory listing of shares
          --shares <list>          Comma-separated list of shares to connect to
          --include-name <name>    Regular expression filter for files to include in the result
          --include-exts <list>    Comma-separated list of file extensions to include in the result.
                                   Mutually exclusive with exclude-ext
          --exclude-exts <list>    Comma-separated list of file extensions to exclude from the result.
                                   Mutually exclusive with include-ext
          --exclude-folders <list> Comma-separated list of folders to not traverse with recursion
          --min-size <int>         Minimum file size to include in results in bytes
          --download <outdir>      Attempt to download all the files in the filtered result set.
      -r, --recurse                Recursively list directories on server
          --follow-links           Follow junctions when listing files. Might lead to loops
          --put-file               Upload --local-file to --remote-path on single share specified by --shares
          --local-file <path>      Path to local file to upload to --remote-path
          --remote-path <path>     Path on share specified by --shares to upload --local-file,
                                   or starting directory for --list (default: share root)
          --replace                Replace any existing file with same name in --remote-path
          --relay                  Start an SMB listener that will relay incoming
                                   NTLM authentications to the remote server and
                                   use that connection. NOTE that this forces SMB 2.1
                                   without encryption.
          --relay-port <port>      Listening port for relay (default 445)
          --socks-host <target>    Establish connection via a SOCKS5 proxy server
          --socks-port <port>      SOCKS5 proxy port (default 1080)
          --noenc                  Disable smb encryption
          --smb2                   Force smb 2.1
          --debug                  Enable debug logging
          --verbose                Enable verbose logging
      -v, --version                Show version
`

type localOptions struct {
	c            *smb.Connection
	interactive  bool
	noInitialCon bool
	smbOptions   *smb.Options
}

func main() {
	var host, username, password, hash, domain, shareFlag, excludeShareFlag, includeName, includeExt, excludeExt, excludeFolder, socksHost, targetIP, dcIP, aesKey, dnsHost, localFile, remotePath string
	var port, socksPort, relayPort int
	var debug, dirList, recurse, shareEnumFlag, noEnc, forceSMB2, localUser, nullSession, version, verbose, relay, noPass, interactive, kerberos, dnsTCP, followJunctions, putFile, replaceFile bool
	var err error
	var dialTimeout time.Duration

	flag.Usage = func() {
		fmt.Println(helpMsg)
		os.Exit(0)
	}

	flag.StringVar(&host, "host", "", "")
	flag.StringVar(&username, "u", "", "")
	flag.StringVar(&username, "user", "", "")
	flag.StringVar(&password, "p", "", "")
	flag.StringVar(&password, "pass", "", "")
	flag.StringVar(&hash, "hash", "", "")
	flag.StringVar(&domain, "d", "", "")
	flag.StringVar(&domain, "domain", "", "")
	flag.IntVar(&port, "P", 445, "")
	flag.IntVar(&port, "port", 445, "")
	flag.BoolVar(&debug, "debug", false, "")
	flag.BoolVar(&verbose, "verbose", false, "")
	flag.StringVar(&shareFlag, "shares", "", "")
	flag.BoolVar(&dirList, "list", false, "")
	flag.BoolVar(&recurse, "r", false, "")
	flag.BoolVar(&recurse, "recurse", false, "")
	flag.BoolVar(&shareEnumFlag, "enum", false, "")
	flag.StringVar(&excludeShareFlag, "exclude", "", "")
	flag.StringVar(&includeName, "include-name", "", "")
	flag.StringVar(&includeExt, "include-exts", "", "")
	flag.StringVar(&excludeExt, "exclude-exts", "", "")
	flag.StringVar(&excludeFolder, "exclude-folders", "", "")
	flag.Uint64Var(&fileSizeThreshold, "min-size", 0, "")
	flag.StringVar(&downloadDir, "download", "", "")
	flag.BoolVar(&noEnc, "noenc", false, "")
	flag.BoolVar(&forceSMB2, "smb2", false, "")
	flag.BoolVar(&localUser, "local", false, "")
	flag.DurationVar(&dialTimeout, "t", 5*time.Second, "")
	flag.DurationVar(&dialTimeout, "timeout", 5*time.Second, "")
	flag.BoolVar(&nullSession, "null", false, "")
	flag.BoolVar(&version, "v", false, "")
	flag.BoolVar(&version, "version", false, "")
	flag.BoolVar(&relay, "relay", false, "")
	flag.IntVar(&relayPort, "relay-port", 445, "")
	flag.StringVar(&socksHost, "socks-host", "", "")
	flag.IntVar(&socksPort, "socks-port", 1080, "")
	flag.BoolVar(&noPass, "no-pass", false, "")
	flag.BoolVar(&noPass, "n", false, "")
	flag.BoolVar(&interactive, "i", false, "")
	flag.BoolVar(&interactive, "interactive", false, "")
	flag.BoolVar(&kerberos, "k", false, "")
	flag.BoolVar(&kerberos, "kerberos", false, "")
	flag.StringVar(&targetIP, "target-ip", "", "")
	flag.StringVar(&dcIP, "dc-ip", "", "")
	flag.StringVar(&aesKey, "aes-key", "", "")
	flag.StringVar(&dnsHost, "dns-host", "", "")
	flag.BoolVar(&dnsTCP, "dns-tcp", false, "")
	flag.BoolVar(&followJunctions, "follow-links", false, "")
	flag.BoolVar(&putFile, "put-file", false, "")
	flag.BoolVar(&replaceFile, "replace", false, "")
	flag.StringVar(&localFile, "local-file", "", "")
	flag.StringVar(&remotePath, "remote-path", "", "")

	flag.Parse()

	if debug {
		golog.Set("github.com/jfjallid/go-smb/smb", "smb", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/spnego", "spnego", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/gss", "gss", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/smb/dcerpc", "dcerpc", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/krb5ssp", "krb5ssp", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		log.SetFlags(golog.LstdFlags | golog.Lshortfile)
		log.SetLogLevel(golog.LevelDebug)
	} else if verbose {
		golog.Set("github.com/jfjallid/go-smb/smb", "smb", golog.LevelInfo, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/spnego", "spnego", golog.LevelInfo, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/gss", "gss", golog.LevelInfo, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/smb/dcerpc", "dcerpc", golog.LevelInfo, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/krb5ssp", "krb5ssp", golog.LevelInfo, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		log.SetLogLevel(golog.LevelInfo)
	} else {
		golog.Set("github.com/jfjallid/go-smb/smb", "smb", golog.LevelNotice, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/spnego", "spnego", golog.LevelNotice, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/gss", "gss", golog.LevelNotice, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/smb/dcerpc", "dcerpc", golog.LevelNotice, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/krb5ssp", "krb5ssp", golog.LevelNotice, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
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

	// Validate format
	if isFlagSet("dns-host") {
		parts := strings.Split(dnsHost, ":")
		if len(parts) < 2 {
			if dnsHost != "" {
				dnsHost += ":53"
				parts = append(parts, "53")
				log.Infof("No port number specified for --dns-host so assuming port 53")
			} else {
				fmt.Println("Invalid --dns-host")
				flag.Usage()
				return
			}
		}
		ip := net.ParseIP(parts[0])
		if ip == nil {
			fmt.Println("Invalid --dns-host. Not a valid ip host address")
			flag.Usage()
			return
		}
		p, err := strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			fmt.Printf("Invalid --dns-host. Failed to parse port: %s\n", err)
			return
		}
		if p < 1 {
			fmt.Println("Invalid --dns-host port number")
			flag.Usage()
			return
		}
	}

	if socksHost != "" && socksPort < 1 {
		fmt.Println("Invalid --socks-port")
		flag.Usage()
		return
	}

	if isFlagSet("download") {
		download = true
		if downloadDir == "" {
			downloadDir = "."
		}
	}

	// Validate regexp if set
	if includeName != "" {
		nameRegexp, err = regexp.Compile(includeName)
		if err != nil {
			log.Errorln(err)
			flag.Usage()
			return
		}
	}

	if includeExt != "" && excludeExt != "" {
		log.Errorln("--include-exts and --exclude-exts are mutually exclusive, so don't supply both!")
		flag.Usage()
		return
	}

	if includeExt != "" {
		includedExts = make(map[string]interface{})
		exts := strings.Split(includeExt, ",")
		for _, e := range exts {
			includedExts[strings.TrimPrefix(strings.TrimSpace(e), ".")] = nil
		}
	}

	if excludeExt != "" {
		excludedExts = make(map[string]interface{})
		exts := strings.Split(excludeExt, ",")
		for _, e := range exts {
			excludedExts[strings.TrimPrefix(strings.TrimSpace(e), ".")] = nil
		}
	}

	if excludeFolder != "" {
		excludedFolders = make(map[string]interface{})
		folders := strings.Split(excludeFolder, ",")
		for _, f := range folders {
			excludedFolders[strings.TrimSpace(f)] = nil
		}
	}

	shares := []string{}
	netShares := []mssrvs.NetShare{}
	var hashBytes []byte
	var aesKeyBytes []byte

	if host == "" && targetIP == "" {
		log.Errorln("Must specify a hostname or ip")
		flag.Usage()
		return
	}
	if host != "" && targetIP == "" {
		targetIP = host
	} else if host == "" && targetIP != "" {
		host = targetIP
	}

	if !shareEnumFlag && !interactive {
		if shareFlag == "" {
			log.Errorln("Please specify a share name or the share enumeration flag.")
			return
		}
		shares = strings.Split(shareFlag, ",")

		if !dirList && !putFile {
			log.Errorln("Please specify share enum flag, list flag or put-file flag!")
			return
		}
	}

	if putFile {
		if len(shares) != 1 {
			log.Errorln("Specify ONE share to upload file to with the --shares argument")
			return
		}
		if localFile == "" {
			log.Errorln("Must specify a --local-file to upload")
			return
		}
		if remotePath == "" {
			log.Errorln("Must specify a --remote-path on share to upload file to")
			return
		}
	}

	if dialTimeout < time.Second {
		log.Errorln("Valid value for the timeout is >= 1 seconds")
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

	if aesKey != "" {
		aesKeyBytes, err = hex.DecodeString(aesKey)
		if err != nil {
			fmt.Println("Failed to decode aesKey")
			log.Errorln(err)
			return
		}
		if len(aesKeyBytes) != 16 && len(aesKeyBytes) != 32 {
			fmt.Println("Invalid keysize of AES Key")
			return
		}
	}

	if noPass {
		password = ""
		hashBytes = nil
		aesKeyBytes = nil
	} else {
		if (password == "") && (hashBytes == nil) && (aesKeyBytes == nil) {
			if (username != "") && (!nullSession) {
				// Check if password is already specified to be empty
				if !isFlagSet("p") && !isFlagSet("pass") {
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
	}

	// Put excluded shares in a map
	parts := strings.Split(excludeShareFlag, ",")
	excludedShares := make(map[string]bool)
	for _, part := range parts {
		excludedShares[part] = true
	}

	if dnsHost != "" {
		protocol := "udp"
		if dnsTCP {
			protocol = "tcp"
		}
		net.DefaultResolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: dialTimeout,
				}
				return d.DialContext(ctx, protocol, dnsHost)
			},
		}
	}

	smbOptions := smb.Options{
		Host:                  targetIP,
		Port:                  port,
		DisableEncryption:     noEnc,
		ForceSMB2:             forceSMB2,
		RequireMessageSigning: false,
		//DisableSigning: true,
	}
	if socksHost != "" {
		dialSocksProxy, err := proxy.SOCKS5("tcp", fmt.Sprintf("%s:%d", socksHost, socksPort), nil, proxy.Direct)
		if err != nil {
			log.Errorln(err)
			return
		}
		smbOptions.ProxyDialer = dialSocksProxy
	}

	if !kerberos && (hashBytes == nil) && (aesKeyBytes == nil) && (password == "") && interactive {
		// Skip login for now
		smbOptions.ManualLogin = true
	}

	if kerberos {
		smbOptions.Initiator = &spnego.KRB5Initiator{
			User:        username,
			Password:    password,
			Domain:      domain,
			Hash:        hashBytes,
			AESKey:      aesKeyBytes,
			SPN:         "cifs/" + host,
			DCIP:        dcIP,
			DialTimeout: dialTimeout,
			ProxyDialer: smbOptions.ProxyDialer,
			DnsHost:     dnsHost,
			DnsTCP:      dnsTCP,
			Host:        host,
		}
	} else {
		smbOptions.Initiator = &spnego.NTLMInitiator{
			User:        username,
			Password:    password,
			Hash:        hashBytes,
			Domain:      domain,
			LocalUser:   localUser,
			NullSession: nullSession,
		}
	}

	smbOptions.DialTimeout = dialTimeout

	var opts localOptions
	opts.smbOptions = &smbOptions // Useful if we want to establish new connections in the shell

	if relay {
		smbOptions.RelayPort = relayPort
		opts.c, err = smb.NewRelayConnection(smbOptions)
	} else {
		opts.c, err = smb.NewConnection(smbOptions)
	}
	if err != nil {
		log.Criticalln(err)
		opts.noInitialCon = true
		if !interactive {
			return
		}
	}

	defer func() {
		if opts.c != nil {
			opts.c.Close()
		}
	}()

	if opts.c != nil {
		if opts.c.IsSigningRequired() {
			log.Noticeln("[-] Signing is required")
		} else {
			log.Noticeln("[+] Signing is NOT required")
		}
	}

	if interactive {
		if opts.c != nil && !opts.c.IsAuthenticated() {
			opts.smbOptions.ManualLogin = true
		}
		shell := newShell(&opts)
		if shell == nil {
			log.Errorln("Failed to start an interactive shell")
			return
		}
		shell.cmdloop()
		return
	}

	if opts.c == nil {
		log.Noticeln("[-] Connection failed")
		return
	}

	if opts.c.IsAuthenticated() {
		log.Noticef("[+] Login successful as %s\n", opts.c.GetAuthUsername())
	} else {
		log.Noticeln("[-] Login failed")
		return
	}

	if putFile {
		if strings.HasPrefix(remotePath, "c:\\") {
			log.Infoln("Stripping prefix c:\\ from remote path")
			remotePath = remotePath[3:]
		}
		log.Infof("Trying to upload local file %q to share %q, path %q\n", localFile, shares[0], remotePath)
		err = uploadFile(opts.c, shares[0], localFile, remotePath, replaceFile)
		if err != nil {
			log.Errorln(err)
			return
		}
		fmt.Println("Successfully uploaded the file")
		return
	} else if shareEnumFlag {
		share := "IPC$"
		err := opts.c.TreeConnect(share)
		if err != nil {
			log.Errorln(err)
			return
		}
		f, err := opts.c.OpenFile(share, "srvsvc")
		if err != nil {
			log.Errorln(err)
			opts.c.TreeDisconnect(share)
			return
		}

		transport, err := smbtransport.NewSMBTransport(f)
		if err != nil {
			log.Errorln(err)
			return
		}
		bind, err := dcerpc.Bind(transport, mssrvs.MSRPCUuidSrvSvc, 3, 0, dcerpc.MSRPCUuidNdr)
		if err != nil {
			log.Errorln("Failed to bind to service")
			log.Errorln(err)
			f.CloseFile()
			opts.c.TreeDisconnect(share)
			return
		}
		rpccon := mssrvs.NewRPCCon(bind)
		log.Infoln("Successfully performed Bind to service")

		result, err := rpccon.NetShareEnumAll(host)
		if err != nil {
			log.Errorln(err)
			f.CloseFile()
			opts.c.TreeDisconnect(share)
			return
		}

		// Replace list of shares when doing enumeration
		shares = []string{}
		for _, netshare := range result {
			name := netshare.Name
			if _, ok := excludedShares[name]; ok {
				// Exclude share
				continue
			}
			netShares = append(netShares, netshare)
			if netshare.TypeId == mssrvs.StypeDisktree {
				shares = append(shares, name)
			}
		}
		f.CloseFile()
		opts.c.TreeDisconnect(share)

		log.Debugf("Retrieved list of %d shares\n", len(shares))

		fmt.Printf("\n#### %s ####\n", host)
		if dirList {
			err = listFiles(opts.c, shares, recurse, followJunctions, remotePath)
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
		err = listFiles(opts.c, shares, recurse, followJunctions, remotePath)
		if err != nil {
			log.Errorln(err)
			return
		}
	}
}
