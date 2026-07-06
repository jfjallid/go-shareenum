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
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	rundebug "runtime/debug"

	"golang.org/x/net/proxy"
	"golang.org/x/term"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/dcerpc/mssrvs"
	"github.com/jfjallid/go-smb/dcerpc/smbtransport"
	"github.com/jfjallid/go-smb/msdtyp"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/relay"
	"github.com/jfjallid/go-smb/spnego"
	"github.com/jfjallid/gokrb5/v9/keytab"
	"github.com/jfjallid/golog"
)

var log = golog.Get("main")
var release string = "0.5.0"
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

// formatUses renders a SHARE_INFO uses counter, mapping the "no limit"
// sentinel (0xffffffff) to a readable string.
func formatUses(v uint32) string {
	if v == 0xffffffff {
		return "unlimited"
	}
	return strconv.FormatUint(uint64(v), 10)
}

// appendNetShare writes a human-readable representation of ns at the given info
// level to sb. Higher levels add more fields: level 501 adds the share flags and
// level 502 additionally carries the permissions, usage counters, on-disk path
// and the share's security descriptor.
func appendNetShare(sb *strings.Builder, ns *mssrvs.NetShare, level int) {
	fmt.Fprintf(sb, "Name: %s\n", ns.Name)
	fmt.Fprintf(sb, "Type: %s\n", ns.Type)
	fmt.Fprintf(sb, "Comment: %s\n", ns.Comment)
	switch level {
	case 501:
		fmt.Fprintf(sb, "Flags: 0x%08x\n", ns.Flags)
	case 502:
		fmt.Fprintf(sb, "Permissions: 0x%08x\n", ns.Permissions)
		fmt.Fprintf(sb, "Max Uses: %s\n", formatUses(ns.MaxUses))
		fmt.Fprintf(sb, "Current Uses: %d\n", ns.CurrentUses)
		fmt.Fprintf(sb, "Path: %s\n", ns.Path)
		if ns.SecurityDescriptor != nil {
			fmt.Fprintln(sb, "Security descriptor:")
			appendSecurityDescriptor(sb, ns.SecurityDescriptor)
		}
	}
}

// appendSecurityDescriptor writes a human-readable representation of sd to sb.
// SIDs are shown in their raw string form as this tool does not resolve them.
func appendSecurityDescriptor(sb *strings.Builder, sd *msdtyp.SecurityDescriptor) {
	if sd == nil {
		return
	}
	if sd.OwnerSid != nil {
		fmt.Fprintf(sb, "OwnerSid: %s\n", sd.OwnerSid.ToString())
	}
	if sd.GroupSid != nil {
		fmt.Fprintf(sb, "GroupSid: %s\n", sd.GroupSid.ToString())
	}
	if sd.Dacl != nil {
		fmt.Fprintln(sb, "DACL entries:")
		appendAceEntries(sb, sd.Dacl.ACLS)
	}
	if sd.Sacl != nil {
		fmt.Fprintln(sb, "SACL entries:")
		appendAceEntries(sb, sd.Sacl.ACLS)
	}
}

// appendAceEntries writes the ACE entries of an ACL to sb.
func appendAceEntries(sb *strings.Builder, aces []msdtyp.ACE) {
	for _, ace := range aces {
		item := ace.Permissions()
		fmt.Fprintf(sb, "AceType: %s\nAceFlags: %s\nSid: %s\n", item.AceType, item.AceFlagStrings, item.Sid)
		sb.WriteString("Permissions: ")
		sb.WriteString(strings.Join(item.Permissions, ","))
		sb.WriteString("\n\n")
	}
}

// getSharesFormatted enumerates the shares on host at the given info level
// (1, 501 or 502) and returns one formatted block per share. Unlike getShares
// it returns every share regardless of type, with the detail the level carries.
func getSharesFormatted(options *localOptions, host string, level int) (lines []string, err error) {
	share := "IPC$"
	err = options.c.TreeConnect(share)
	if err != nil {
		return
	}
	defer options.c.TreeDisconnect(share)
	f, err := options.c.OpenFile(share, "srvsvc")
	if err != nil {
		return
	}
	defer f.CloseFile()
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
		return
	}
	rpccon := mssrvs.NewRPCCon(bind)

	netshares, err := rpccon.NetShareEnumAllExt(host, level)
	if err != nil {
		return
	}
	for i := range netshares {
		var sb strings.Builder
		appendNetShare(&sb, &netshares[i], level)
		lines = append(lines, sb.String())
	}
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
			if errors.Is(err, smb.StatusMap[smb.StatusBadNetworkName]) {
				fmt.Printf("Share %s can not be found!\n", share)
				continue
			}
			log.Errorln(err)
			continue
		}
		files, err := session.ListDirectory(share, dir, "")
		if err != nil {

			if errors.Is(err, smb.StatusMap[smb.StatusAccessDenied]) {
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

	// Strip a leading drive-letter prefix (e.g. c:\, D:\); the share is the volume.
	remotePath = stripDrivePrefix(remotePath)

	if remotePath == "" {
		err = fmt.Errorf("remote path must not be empty")
		return
	}

	// Check if remotePath specifies filename
	if remotePath[len(remotePath)-1] == '\\' {
		remotePath += "\\" + filename
	}

	// Strip any leading separators to get the share-relative path
	modifiedRemoteFile := strings.TrimLeft(remotePath, "\\")

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
		if errors.Is(err, smb.StatusMap[smb.StatusObjectNameCollision]) {
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

// stripDrivePrefix removes a leading Windows drive-letter prefix such as
// "c:\" or "D:\" from a path that already uses backslash separators. A share
// is itself a volume, so a drive-qualified path from the caller is redundant;
// dropping the prefix yields the share-relative path. Only the "<letter>:\"
// form is stripped; a bare "c:" with no separator is left as-is.
func stripDrivePrefix(remotePath string) string {
	if len(remotePath) >= 3 &&
		remotePath[1] == ':' && remotePath[2] == '\\' {
		c := remotePath[0]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			log.Infof("Stripping drive prefix %q from remote path\n", remotePath[:3])
			return remotePath[3:]
		}
	}
	return remotePath
}

func downloadFile(conn *smb.Connection, share, remotePath, localFile string, replaceFile bool) (err error) {
	// Remote paths should use Windows path separators
	remotePath = strings.ReplaceAll(remotePath, "/", "\\")

	// Strip a leading drive-letter prefix (e.g. c:\, D:\) so callers may pass
	// Windows-style absolute paths; the share is already the volume.
	remotePath = stripDrivePrefix(remotePath)

	if remotePath == "" {
		err = fmt.Errorf("remote path must not be empty")
		return
	}

	// A path ending in a separator has no filename to download
	if remotePath[len(remotePath)-1] == '\\' {
		err = fmt.Errorf("remote path %q does not specify a filename", remotePath)
		return
	}

	// Strip any leading separators to get the share-relative path
	modifiedRemoteFile := strings.TrimLeft(remotePath, "\\")

	// Derive the remote filename (last path element) for the local destination
	remoteFilename := modifiedRemoteFile
	if idx := strings.LastIndex(modifiedRemoteFile, "\\"); idx != -1 {
		remoteFilename = modifiedRemoteFile[idx+1:]
	}
	if remoteFilename == "" {
		err = fmt.Errorf("could not determine filename from remote path %q", remotePath)
		return
	}
	if localFile == "" {
		localFile = remoteFilename
	}

	// Open the local destination, refusing to overwrite unless --replace was set
	f, err := os.OpenFile(localFile, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0640)
	if err != nil {
		if os.IsExist(err) {
			if !replaceFile {
				log.Errorf("The local file %q already exists. Run with --replace to overwrite it\n", localFile)
				return
			}
			f, err = os.OpenFile(localFile, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0640)
			if err != nil {
				log.Errorln(err)
				return
			}
		} else {
			log.Errorln(err)
			return
		}
	}
	defer f.Close()

	log.Infof("Trying to download the remote file %s from share: %s to local file: %s\n", modifiedRemoteFile, share, localFile)
	err = conn.RetrieveFile(share, modifiedRemoteFile, 0, f.Write)
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
          --keytab-file <file>     Authenticate using keys from a keytab file (implies -k). User and
                                   domain are taken from the first keytab entry if not specified
      -t, --timeout <duration>     Dial timeout specified in 5s, 1m, 10m format (default 5s)
          --enum                   List available SMB shares
          --level <int>            Info level for --enum: 1, 501 or 502 (default 1).
                                   Higher levels add the share flags (501) and the
                                   permissions, path and security descriptor (502)
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
          --get-file               Download --remote-path from single share specified by --shares to
                                   --local-file (defaults to the remote filename in the cwd)
          --local-file <path>      Path to local file to upload to --remote-path (--put-file), or
                                   local destination for a --get-file download (optional for --get-file)
          --remote-path <path>     Path on share specified by --shares to upload --local-file,
                                   file to download with --get-file, or starting directory for
                                   --list (default: share root)
          --replace                Replace any existing file with same name in --remote-path when
                                   uploading, or the existing local file when downloading
      -c "<cmd1>; <cmd2>"          Run semicolon-separated commands non-interactively, then exit.
                                   Commands match the interactive shell. No escape syntax for ';';
                                   use --script for commands containing literal semicolons.
          --script <file>          Run commands from <file> (one per line; blank lines and lines
                                   starting with '#' are ignored). Same command set as -c.
          --relay                  Start an SMB listener that will relay incoming
                                   NTLM authentications to the remote server and
                                   use that connection. NOTE that this forces SMB 2.1
                                   without encryption.
          --relay-port <port>      Listening port for relay (default 445)
          --socks-host <target>    Establish connection via a SOCKS5 proxy server
          --socks-port <port>      SOCKS5 proxy port (default 1080)
          --noenc                  Disable smb encryption
          --smb2                   Force smb 2.1
          --debug                  Enable debug logging. Bare --debug turns on every
                                   registered package; --debug=smb,relay turns on only the
                                   listed package-name suffixes (the '=' form is required
                                   for the filter).
          --verbose                Enable verbose logging. Same filter syntax as --debug.
                                   --debug and --verbose may be combined with different
                                   filters; a package targeted by both gets the higher level.
          --list-log-packages      List the registered log package names that can be
                                   targeted with --debug=<suffix> or --verbose=<suffix>,
                                   then exit
      -v, --version                Show version
`

type localOptions struct {
	c            *smb.Connection
	interactive  bool
	noInitialCon bool
	smbOptions   *smb.Options
}

// logFlag is a comma-separated package-suffix filter that also remembers
// whether the user passed the flag at all. IsBoolFlag is set so the bare
// "--debug" and "--verbose" form parses (flag pkg then calls Set("true"))
// — we treat "true" as "no filter, all packages on". A filter list requires
// the "=" form, e.g. --debug=smb,relay, because IsBoolFlag stops the parser
// from consuming the next positional token.
type logFlag struct {
	set    bool
	values []string
}

func (d *logFlag) String() string { return strings.Join(d.values, ",") }

func (d *logFlag) IsBoolFlag() bool { return true }

func (d *logFlag) Set(s string) error {
	d.set = true
	d.values = nil
	if s == "" || s == "true" {
		return nil
	}
	for _, tok := range strings.Split(s, ",") {
		if tok = strings.TrimSpace(tok); tok != "" {
			d.values = append(d.values, tok)
		}
	}
	return nil
}

// applyLogLevel bumps registered package loggers to level. An empty filter
// matches every name returned by golog.Names(); a non-empty filter keeps only
// names whose path suffix matches one of the tokens (see matchesAny).
func applyLogLevel(level int, filter []string) {
	flags := golog.LstdFlags | golog.Lshortfile
	for _, name := range golog.Names() {
		if len(filter) == 0 || matchesAny(name, filter) {
			golog.Set(name, "", level, flags, nil, nil)
		}
	}
}

// matchesAny reports whether name equals any token or ends with "/"+token,
// so "smb" hits ".../go-smb/smb" but not ".../go-smb" (ends in "/go-smb",
// not "/smb") and not ".../smb/server" (ends in "/server").
func matchesAny(name string, tokens []string) bool {
	for _, t := range tokens {
		if name == t || strings.HasSuffix(name, "/"+t) {
			return true
		}
	}
	return false
}

func main() {
	var host, username, password, hash, domain, shareFlag, excludeShareFlag, includeName, includeExt, excludeExt, excludeFolder, socksHost, targetIP, dcIP, aesKey, dnsHost, localFile, remotePath, batchCmd, scriptFile, keytabFile string
	var port, socksPort, relayPort, level int
	var dirList, recurse, shareEnumFlag, noEnc, forceSMB2, localUser, nullSession, version, doRelay, noPass, interactive, kerberos, dnsTCP, followJunctions, putFile, getFile, replaceFile, listLogPackages bool
	var debug, verbose logFlag
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
	flag.Var(&debug, "debug", "")
	flag.Var(&verbose, "verbose", "")
	flag.StringVar(&shareFlag, "shares", "", "")
	flag.BoolVar(&dirList, "list", false, "")
	flag.BoolVar(&recurse, "r", false, "")
	flag.BoolVar(&recurse, "recurse", false, "")
	flag.BoolVar(&shareEnumFlag, "enum", false, "")
	flag.IntVar(&level, "level", 1, "")
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
	flag.BoolVar(&listLogPackages, "list-log-packages", false, "")
	flag.BoolVar(&doRelay, "relay", false, "")
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
	flag.StringVar(&keytabFile, "keytab-file", "", "")
	flag.StringVar(&dnsHost, "dns-host", "", "")
	flag.BoolVar(&dnsTCP, "dns-tcp", false, "")
	flag.BoolVar(&followJunctions, "follow-links", false, "")
	flag.BoolVar(&putFile, "put-file", false, "")
	flag.BoolVar(&getFile, "get-file", false, "")
	flag.BoolVar(&replaceFile, "replace", false, "")
	flag.StringVar(&localFile, "local-file", "", "")
	flag.StringVar(&remotePath, "remote-path", "", "")
	flag.StringVar(&batchCmd, "c", "", "")
	flag.StringVar(&scriptFile, "script", "", "")

	flag.Parse()

	if listLogPackages {
		// The package loggers are registered at import time, so golog.Names()
		// here lists every logger this binary can target. The suffix of any of
		// these names (a path segment) is what --debug=/--verbose= matches.
		names := golog.Names()
		sort.Strings(names)
		fmt.Println("Registered log packages (target a name's suffix with --debug=<suffix> or --verbose=<suffix>):")
		for _, name := range names {
			fmt.Println(name)
		}
		return
	}

	// --debug and --verbose are not mutually exclusive: each may carry its own
	// comma-separated package filter (e.g. --debug=smb,relay --verbose=main).
	// Verbose is applied first and debug second so that any package targeted by
	// both ends up at the higher level (LevelDebug > LevelInfo). A bare --debug
	// or --verbose (empty filter) targets every registered package, so passing
	// both bare is ambiguous and rejected.
	if debug.set || verbose.set {
		if debug.set && verbose.set && len(debug.values) == 0 && len(verbose.values) == 0 {
			fmt.Println("Cannot enable both --debug and --verbose for all packages at once. Specify just one of them, or be more granular e.g. --debug=smb,relay --verbose=main")
			return
		}
		if verbose.set {
			applyLogLevel(golog.LevelInfo, verbose.values)
		}
		if debug.set {
			applyLogLevel(golog.LevelDebug, debug.values)
		}
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

	batch := batchCmd != "" || scriptFile != ""
	if batchCmd != "" && scriptFile != "" {
		log.Errorln("-c and --script are mutually exclusive")
		return
	}
	if batch && (interactive || shareEnumFlag || dirList || putFile || getFile) {
		log.Errorln("Batch mode (-c/--script) is mutually exclusive with --interactive, --enum, --list, --put-file, and --get-file")
		return
	}

	if putFile && getFile {
		log.Errorln("--put-file and --get-file are mutually exclusive")
		return
	}

	if !shareEnumFlag && !interactive && !batch {
		if shareFlag == "" {
			log.Errorln("Please specify a share name or the share enumeration flag.")
			return
		}
		shares = strings.Split(shareFlag, ",")

		if !dirList && !putFile && !getFile {
			log.Errorln("Please specify share enum flag, list flag, put-file flag or get-file flag!")
			return
		}
	}

	if isFlagSet("level") {
		if !shareEnumFlag {
			log.Errorln("--level can only be used together with --enum")
			return
		}
		switch level {
		case 1, 501, 502:
		default:
			log.Errorln("Invalid --level for --enum (supported: 1, 501, 502)")
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

	if getFile {
		if len(shares) != 1 {
			log.Errorln("Specify ONE share to download file from with the --shares argument")
			return
		}
		if remotePath == "" {
			log.Errorln("Must specify a --remote-path on share to download file from")
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

	// A keytab is a Kerberos credential, so authenticating with one implies -k.
	if keytabFile != "" {
		kerberos = true
	}

	if noPass {
		password = ""
		hashBytes = nil
		aesKeyBytes = nil
	} else {
		// A keytab is a valid credential source, so don't prompt for a password
		// when one is supplied.
		if (password == "") && (hashBytes == nil) && (aesKeyBytes == nil) && (keytabFile == "") {
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
		//RequireMessageSigning: true,
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
		krbInitiator := &spnego.KRB5Initiator{
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
		if keytabFile != "" {
			// The initiator authenticates from the keytab and derives a missing
			// User/Domain from its first entry.
			kt, kerr := keytab.Load(keytabFile)
			if kerr != nil {
				log.Errorf("Failed to load keytab file %s: %s\n", keytabFile, kerr)
				return
			}
			krbInitiator.Keytab = kt
		}
		smbOptions.Initiator = krbInitiator
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

	if doRelay {
		relayConf := relay.ClientConfig{
			ListenAddr: fmt.Sprintf(":%d", relayPort),
			Target: fmt.Sprintf("%s:445", targetIP),
			UpstreamOptions: smbOptions,
		}
		opts.c, _, err = relay.RelayClient(relayConf)
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

	if batch {
		rc := runBatchMode(&opts, batchCmd, scriptFile, debug.set, verbose.set)
		if opts.c != nil {
			opts.c.Close()
			opts.c = nil
		}
		os.Exit(rc)
	}

	if putFile {
		log.Infof("Trying to upload local file %q to share %q, path %q\n", localFile, shares[0], remotePath)
		err = uploadFile(opts.c, shares[0], localFile, remotePath, replaceFile)
		if err != nil {
			log.Errorln(err)
			return
		}
		fmt.Println("Successfully uploaded the file")
		return
	} else if getFile {
		log.Infof("Trying to download remote path %q from share %q to local file %q\n", remotePath, shares[0], localFile)
		err = downloadFile(opts.c, shares[0], remotePath, localFile, replaceFile)
		if err != nil {
			log.Errorln(err)
			return
		}
		fmt.Println("Successfully downloaded the file")
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

		result, err := rpccon.NetShareEnumAllExt(host, level)
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
			if isFlagSet("level") {
				// Detailed enumeration with the fields the chosen level carries.
				for i := range netShares {
					var sb strings.Builder
					appendNetShare(&sb, &netShares[i], level)
					fmt.Println(sb.String())
				}
			} else {
				for _, share := range netShares {
					fmt.Printf("Name: %s\nComment: %s\nHidden: %v\nType: %s\n\n", share.Name, share.Comment, share.Hidden, share.Type)
				}
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
