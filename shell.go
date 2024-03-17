// MIT License
//
// # Copyright (c) 2024 Jimmy Fjällid
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
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/dcerpc"
	"github.com/jfjallid/golog"
	"golang.org/x/term"
)

var (
	scanner  *bufio.Scanner
	handlers = make(map[string]interface{})
)

type shell struct {
	options       *localOptions
	prompt        string
	lcwd          string
	rcwd          string
	share         string
	authenticated bool
	t             *term.Terminal
}

// Inspired by Impacket's smbclient.py
var helpMsgShell string = `Commands:
   open <host> [port]                    - opens a new SMB connection against the target host/port
   login [domain/username] [passwd]      - logs into the current SMB connection, no parameters for NULL connection
   login_hash [domain/username] [nthash] - logs into the current SMB connection using the password hashes
   logout                                - ends the current SMB session but keeps the connection
   shares                                - list available shares
   use <sharename>                       - connect to an specific share
   cd <path>                             - changes the current directory to {path}
   lcd <path>                            - changes the current local directory to {path}
   pwd                                   - shows current remote working directory
   ls [dir] [pattern]                    - lists files in dir filtered by pattern
   lls [dir]                             - lists files in dir on the local filesystem
   rm <file>                             - removes the selected file from the current directory
   mkdir <path>                          - creates the directory specified by <path>
   rmdir <path>                          - removes the directory specified by <path>
   put <filename>                        - uploads the filename into the current directory
   get <filename>                        - downloads the filename from the current directory
   mget <mask>                           - downloads all files from the current directory matching the provided mask
   cat <filename>                        - reads the content of <filename> and prints to stdout
   info                                  - returns NetServerInfo results (admin gets more info)
   who                                   - returns the sessions currently connected at the target host (admin required)
   close                                 - closes the current SMB connection
   exit                                  - terminates the server process (and this session)
`

func (self *shell) getConfirmation(s string) bool {
	self.t.SetPrompt("")
	defer self.t.SetPrompt(self.prompt)

	self.printf("%s [y/n]: ", s)
	response, err := self.t.ReadLine()
	if err != nil {
		log.Errorln(err)
		return false
	}
	response = strings.ToLower(strings.TrimSpace(response))
	if response == "y" || response == "yes" {
		return true
	}
	return false
}

func mergePaths(base, target string) string {
	targetDir := filepath.Join(base, target)
	targetDir = filepath.Clean(targetDir)
	targetDir = strings.ReplaceAll(targetDir, `\`, `/`) // Try to only have one type of separator
	targetDir = filepath.FromSlash(targetDir)
	return filepath.Clean(targetDir)
}

func newShell(o *localOptions) *shell {
	s := shell{
		options:       o,
		prompt:        "# ",
		rcwd:          string(filepath.Separator),
		authenticated: true,
	}
	cwd, err := os.Getwd()
	if err != nil {
		log.Errorln(err)
		return nil
	}
	s.lcwd = cwd
	handlers["help"] = s.showHelpFunc
	handlers["?"] = s.showHelpFunc
	handlers["shares"] = s.listSharesFunc
	handlers["use"] = s.useShareFunc
	handlers["ls"] = s.listFilesFunc
	handlers["lls"] = s.listLocalFilesFunc
	handlers["cd"] = s.changeDirFunc
	handlers["lcd"] = s.changeLocalDirFunc
	handlers["pwd"] = s.printCWDFunc
	handlers["lpwd"] = s.printLocalCWDFunc
	handlers["mkdir"] = s.mkdirFunc
	handlers["rmdir"] = s.rmdirFunc
	handlers["cat"] = s.catFunc
	handlers["get"] = s.getFileFunc
	handlers["put"] = s.putFileFunc
	handlers["rm"] = s.rmFileFunc
	handlers["mget"] = s.maskGetFilesFunc
	handlers["info"] = s.getServerInfoFunc
	handlers["who"] = s.getSessionsFunc
	handlers["open"] = s.openConnectionFunc
	handlers["close"] = s.closeConnectionFunc
	handlers["login"] = s.loginFunc
	handlers["login_hash"] = s.loginHashFunc
	handlers["logout"] = s.logoutFunc
	return &s
}

func (self *shell) showHelpFunc(args interface{}) {
	self.println(helpMsgShell)
}

func (self *shell) listSharesFunc(args interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	shares, err := getShares(self.options, "")
	if err != nil {
		self.println(err)
		return
	}
	for _, share := range shares {
		self.println(share)
	}
}

func (self *shell) printCWDFunc(args interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	if self.share == "" {
		self.println("You haven't connected to any shares yet")
		return
	}
	self.println(self.rcwd)
}

func (self *shell) printLocalCWDFunc(args interface{}) {
	self.println(self.lcwd)
}

func (self *shell) useShareFunc(argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	args := argArr.([]string)

	if len(args) != 1 {
		self.println("Must specify a share name with 'use' command")
		return
	}
	err := self.options.c.TreeConnect(args[0])
	if err != nil {
		self.println(err)
	}
	self.share = args[0]
	self.rcwd = string(filepath.Separator)
}

func (self *shell) listLocalFilesFunc(argArr interface{}) {
	args := argArr.([]string)
	target := ""
	if len(args) > 0 {
		target = strings.Join(args, " ")
	}

	if !filepath.IsAbs(target) {
		target = mergePaths(self.lcwd, target)
	}
	files, err := ioutil.ReadDir(target)
	if err != nil {
		self.println(err)
		return
	}
	for _, f := range files {
		self.println(f.Name())
	}
}

func (self *shell) printFiles(files []smb.SharedFile) {
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
			self.printf("%-4s  %11d  %-30s  %s\n", fileType, file.Size, lastWrite, file.Name)
		}
	}
}

func (self *shell) listFilesFunc(argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	if self.share == "" {
		self.println("Must connect to a share before listing files!")
		return
	}

	/*
	   ls *.exe : only pattern
	   ls dir : only pattern
	   ls dir/ : only path
	   ls dir / *.exe path + pattern
	   ls / : only path
	   ls / *.exe : path + pattern
	   ls /my dir/ : only path
	   ls /my dir/ *.exe : path + pattern
	   a pattern should never end with a forward och backward slash
	*/
	args := argArr.([]string)
	dir := ""
	pattern := ""
	numArgs := len(args)
	if numArgs > 0 {
		lastArg := args[numArgs-1]
		if strings.ContainsAny(string(lastArg[len(lastArg)-1]), `/\`) {
			// Only path, no pattern
			dir = strings.Join(args, " ")
		} else {
			// If there are multiple args, last one is pattern and the rest are the path
			// However, if there is only one arg it is a pattern unless it contains slashes
			if numArgs == 1 {
				// Could a pattern ever contain slashes?
				if strings.ContainsAny(args[0], `/\`) {
					dir = args[0]
				} else {
					pattern = args[0]
				}
			} else {
				dir = strings.Join(args[:numArgs-1], " ")
				pattern = lastArg
			}
		}

		if !filepath.IsAbs(dir) && dir != `\` {
			dir = mergePaths(self.rcwd, dir)
		}
	}

	/*
	   If dir is populated, check if it is absolute path and if so, use it
	   If dir is populated with a relative path, combine with rcwd
	*/
	if dir == "" {
		dir = self.rcwd
	}

	if dir == "/" || dir == `\` || dir == "" {
		// List absolute path to root dir
		dir = ""
	} else {
		dir = strings.ReplaceAll(dir[1:], `/`, `\`)
		dir = strings.TrimRight(dir, `/\`)
	}

	files, err := self.options.c.ListDirectory(self.share, dir, pattern)
	if err != nil {
		if err == smb.StatusMap[smb.StatusAccessDenied] {
			self.println("Listing files was prohibited!")
			return
		}
		self.println(err)
		return
	}
	self.printFiles(files)
}

func (self *shell) changeDirFunc(argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	if self.share == "" {
		self.println("Must connect to a share before changing working directory!")
		return
	}

	args := argArr.([]string)
	if len(args) == 0 {
		self.println("Invalid directory")
		return
	}

	targetDir := strings.Join(args, " ")
	// Not perfect, might want to allow cd / on windows to also go to root dir
	if !filepath.IsAbs(targetDir) && string(targetDir[0]) != `\` {
		targetDir = mergePaths(self.rcwd, targetDir)
	}

	if targetDir == "/" {
		self.rcwd = "/"
		return
	}

	modifiedTargetDir := strings.ReplaceAll(targetDir[1:], `/`, `\`)

	//Open the file targetDir to see that it exists and then close it again
	createOpts := smb.NewCreateReqOpts()
	createOpts.DesiredAccess = smb.DAccMaskFileListDirectory
	createOpts.CreateOpts = smb.FileDirectoryFile

	f, err := self.options.c.OpenFileExt(self.share, modifiedTargetDir, createOpts)
	if err != nil {
		self.println(err)
		return
	}

	self.rcwd = targetDir
	f.CloseFile()
}

func (self *shell) changeLocalDirFunc(argArr interface{}) {
	args := argArr.([]string)
	if len(args) == 0 {
		self.println("Invalid directory")
		return
	}
	targetDir := strings.Join(args, " ")

	if !filepath.IsAbs(targetDir) {
		targetDir = mergePaths(self.lcwd, targetDir)
	}

	targetDir = filepath.Clean(targetDir)

	err := os.Chdir(targetDir)
	if err != nil {
		self.println(err)
		return
	}
	self.lcwd = targetDir
}

func (self *shell) mkdirFunc(argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	if self.share == "" {
		self.println("Must connect to a share before creating a new directory!")
		return
	}

	args := argArr.([]string)
	if len(args) == 0 {
		self.println("Invalid directory")
		return
	}

	targetDir := mergePaths(self.rcwd, strings.Join(args, " "))

	modifiedTargetDir := strings.ReplaceAll(targetDir, `/`, `\`)[1:]
	err := self.options.c.Mkdir(self.share, modifiedTargetDir)
	if err != nil {
		self.println(err)
		return
	}
}

func (self *shell) rmdirFunc(argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	if self.share == "" {
		self.println("Must connect to a share before creating a new directory!")
		return
	}

	args := argArr.([]string)
	if len(args) == 0 {
		self.println("Invalid directory")
		return
	}

	targetDir := mergePaths(self.rcwd, strings.Join(args, " "))

	modifiedTargetDir := strings.ReplaceAll(targetDir, `/`, `\`)[1:]
	err := self.options.c.DeleteDir(self.share, modifiedTargetDir)
	if err != nil {
		self.println(err)
		return
	}
}

func (self *shell) catFunc(argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	if self.share == "" {
		self.println("Must connect to a share before attempting to read a file!")
		return
	}

	args := argArr.([]string)
	if len(args) == 0 {
		self.println("Invalid filename")
		return
	}
	filename := strings.Join(args, " ")
	if strings.ContainsAny(filename, `/\`) {
		self.println("Invalid filename!")
		return
	}

	targetFile := filepath.Join(self.rcwd, filename)

	modifiedTargetFile := strings.ReplaceAll(targetFile, `/`, `\`)[1:]
	f, err := self.options.c.OpenFile(self.share, modifiedTargetFile)
	if err != nil {
		self.println(err)
		return
	}
	chunkSize := 2048
	if int(f.FileMetadata.EndOfFile) > chunkSize {
		if !self.getConfirmation(fmt.Sprintf("%s is %d bytes long, sure you want to print it to stdout?", filename, f.FileMetadata.EndOfFile)) {
			return
		}
		chunkSize = int(f.FileMetadata.EndOfFile)
	}
	defer f.CloseFile()
	fileChunk := make([]byte, chunkSize)
	n, err := f.ReadFile(fileChunk, 0)
	if err != nil {
		self.println(err)
		return
	}
	self.printf("%s", fileChunk[:n])
}

func (self *shell) getFileFunc(argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	if self.share == "" {
		self.println("Must connect to a share before attempting to download a file!")
		return
	}

	args := argArr.([]string)
	if len(args) == 0 {
		self.println("Invalid filename")
		return
	}
	filename := strings.Join(args, " ")
	if strings.ContainsAny(filename, `/\`) {
		self.println("Invalid filename!")
		return
	}

	localFile := filepath.Join(self.lcwd, filename)
	targetFile := filepath.Join(self.rcwd, filename)

	modifiedTargetFile := strings.ReplaceAll(targetFile, `/`, `\`)[1:]

	// Open local file in the subdir and start downloading the file
	f, err := os.OpenFile(localFile, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0640)
	if err != nil {
		if os.IsExist(err) {
			if !self.getConfirmation(fmt.Sprintf("The local file %s already exists. Do you want to replace it?", filename)) {
				return
			}
			f, err = os.OpenFile(localFile, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0640)
			if err != nil {
				self.println(err)
				return
			}
		} else {
			self.println(err)
			return
		}
	}

	err = self.options.c.RetrieveFile(self.share, modifiedTargetFile, 0, f.Write)
	if err != nil {
		self.println(err)
		f.Close()
		return
	}
	f.Close()
}

func (self *shell) putFileFunc(argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}

	if self.share == "" {
		self.println("Must connect to a share before attempting to upload a file!")
		return
	}

	var err error
	var localFile *os.File
	args := argArr.([]string)
	if len(args) == 0 {
		self.println("Invalid filename!")
		return
	}
	filename := strings.Join(args, " ")
	if strings.ContainsAny(filename, `/\`) {
		self.println("Invalid filename!")
		return
	}

	sourceFile := filepath.Join(self.lcwd, filename)
	remoteFile := filepath.Join(self.rcwd, filename)

	modifiedRemoteFile := strings.ReplaceAll(remoteFile, `/`, `\`)[1:]

	// Check that local file exists
	localFile, err = os.Open(sourceFile)
	if err != nil {
		if os.IsNotExist(err) {
			self.println("The local filename does not exist")
			return
		}
		self.println(err)
		return
	}
	defer localFile.Close()

	// Check if remote file exists, and if so, ask before replacing it
	createOpts := smb.NewCreateReqOpts()
	createOpts.CreateDisp = smb.FileCreate
	f, err := self.options.c.OpenFileExt(self.share, modifiedRemoteFile, createOpts)
	if err != nil {
		// Check if file exists and we want to replace it
		if err == smb.StatusMap[smb.StatusObjectNameCollision] {
			if !self.getConfirmation(fmt.Sprintf("The remote file %s already exists. Do you want to replace it?", remoteFile)) {
				return
			}
			// Continue and replace the remote file
		} else {
			self.println(err)
			return
		}
	} else {
		f.CloseFile()
	}

	err = self.options.c.PutFile(self.share, modifiedRemoteFile, 0, localFile.Read)
	if err != nil {
		self.println(err)
		return
	}
}

func (self *shell) rmFileFunc(argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	if self.share == "" {
		self.println("Must connect to a share before attempting to delete a file!")
		return
	}

	args := argArr.([]string)
	if len(args) == 0 {
		self.println("Invalid filename")
		return
	}
	// Only allow filenames and not paths
	filename := strings.Join(args, " ")
	if strings.ContainsAny(filename, `/\`) {
		self.println("Invalid filename!")
		return
	}

	targetFile := filepath.Join(self.rcwd, filename)
	modifiedTargetFile := strings.ReplaceAll(targetFile, `/`, `\`)[1:]

	err := self.options.c.DeleteFile(self.share, modifiedTargetFile)
	if err != nil {
		self.println(err)
	}
	return
}

func (self *shell) maskGetFilesFunc(argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	if self.share == "" {
		self.println("Must connect to a share before attempting to download files!")
		return
	}

	args := argArr.([]string)
	if len(args) == 0 {
		self.println("Invalid mask")
		return
	}

	pattern := strings.Join(args, " ")
	if strings.ContainsAny(pattern, `/\`) {
		self.println("Invalid mask")
		return
	}

	modifiedRCWD := strings.ReplaceAll(self.rcwd, `/`, `\`)[1:]

	downloadDir = self.lcwd
	files, err := self.options.c.ListDirectory(self.share, modifiedRCWD, pattern)
	if err != nil {
		self.println(err)
		return
	}
	downloadFiles(self.options.c, self.share, files, false)
}

func (self *shell) getServerInfoFunc(argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	share := "IPC$"
	err := self.options.c.TreeConnect(share)
	if err != nil {
		self.println(err)
		return
	}
	f, err := self.options.c.OpenFile(share, "srvsvc")
	if err != nil {
		self.println(err)
		self.options.c.TreeDisconnect(share)
		return
	}

	bind, err := dcerpc.Bind(f, dcerpc.MSRPCUuidSrvSvc, 3, 0, dcerpc.MSRPCUuidNdr)
	if err != nil {
		self.println("Failed to bind to service")
		self.println(err)
		f.CloseFile()
		self.options.c.TreeDisconnect(share)
		return
	}

	result, err := bind.NetServerGetInfo("", 102)
	if err != nil {
		if err == dcerpc.SRVSResponseCodeMap[dcerpc.SRVSErrorAccessDenied] {
			result, err = bind.NetServerGetInfo("", 101)
			if err != nil {
				self.println(err)
				f.CloseFile()
				self.options.c.TreeDisconnect(share)
				return
			}
		} else {
			self.println(err)
			f.CloseFile()
			self.options.c.TreeDisconnect(share)
			return
		}
	}
	switch result.Level {
	case 101:
		si := result.Pointer.(*dcerpc.NetServerInfo101)
		self.printf("Version Major: %d\n", si.VersionMajor)
		self.printf("Version Minor: %d\n", si.VersionMinor)
		self.printf("Server Name: %s\n", si.Name)
		self.printf("Server Comment: %s\n", si.Comment)
	case 102:
		si := result.Pointer.(*dcerpc.NetServerInfo102)
		self.printf("Version Major: %d\n", si.VersionMajor)
		self.printf("Version Minor: %d\n", si.VersionMinor)
		self.printf("Server Name: %s\n", si.Name)
		self.printf("Server Comment: %s\n", si.Comment)
		self.printf("Server UserPath: %s\n", si.Userpath)
		self.printf("Simultaneous Users: %d\n", si.Users)
	default:
		self.printf("Unknown result with level %d\n", result.Level)
	}

	f.CloseFile()
	self.options.c.TreeDisconnect(share)
	return
}

func (self *shell) getSessionsFunc(argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	share := "IPC$"
	err := self.options.c.TreeConnect(share)
	if err != nil {
		self.println(err)
		return
	}
	f, err := self.options.c.OpenFile(share, "srvsvc")
	if err != nil {
		self.println(err)
		self.options.c.TreeDisconnect(share)
		return
	}

	bind, err := dcerpc.Bind(f, dcerpc.MSRPCUuidSrvSvc, 3, 0, dcerpc.MSRPCUuidNdr)
	if err != nil {
		self.println("Failed to bind to service")
		self.println(err)
		f.CloseFile()
		self.options.c.TreeDisconnect(share)
		return
	}

	result, err := bind.NetSessionEnum("", "", 10)
	if err != nil {
		self.println(err)
		f.CloseFile()
		self.options.c.TreeDisconnect(share)
		return
	}
	switch result.Level {
	case 0:
		sic := result.SessionInfo.(*dcerpc.SessionInfoContainer0)
		for i := 0; i < int(sic.EntriesRead); i++ {
			si := sic.Buffer[i]
			self.printf("host: %s\n", si.Cname)
		}
	case 10:
		sic := result.SessionInfo.(*dcerpc.SessionInfoContainer10)
		for i := 0; i < int(sic.EntriesRead); i++ {
			si := sic.Buffer[i]
			self.printf("host: %s, user: %s, active: %6d, idle: %6d\n", si.Cname, si.Username, si.Time, si.IdleTime)
		}
	case 502:
		sic := result.SessionInfo.(*dcerpc.SessionInfoContainer502)
		for i := 0; i < int(sic.EntriesRead); i++ {
			si := sic.Buffer[i]
			guest := si.UserFlags&0x1 == 0x1
			noEnc := si.UserFlags&0x2 == 0x2

			self.printf("host: %s, user: %s, clienttype %s, transport: %s, guest: %v, noEnc: %v, active: %6d, idle: %6d, numOpens: %6d\n", si.Cname, si.Username, si.ClType, si.Transport, guest, noEnc, si.Time, si.IdleTime, si.NumOpens)
		}
	default:
		self.printf("Unknown result with level %d\n", result.Level)
	}

	f.CloseFile()
	self.options.c.TreeDisconnect(share)
	return
}

func (self *shell) openConnectionFunc(argArr interface{}) {
	var err error
	if self.options.c != nil {
		self.println("Closing existing connection first")
		self.closeConnection()
		self.options.c = nil
	}
	args := argArr.([]string)
	if len(args) < 1 {
		self.println("Invalid arguments. Expected host and optionally a port parameter")
		return
	}
	host := args[0]
	port := 445
	if len(args) > 1 {
		portStr := args[1]
		port, err = strconv.Atoi(portStr)
		if err != nil {
			self.printf("Failed to parse port as number: %s\n", err)
			return
		}
		if port < 1 || port > 65535 {
			self.println("Invalid port!")
			return
		}
	}

	self.options.smbOptions.Host = host
	self.options.smbOptions.Port = port
	self.options.smbOptions.Initiator = nil
	self.options.smbOptions.ManualLogin = true
	self.options.c, err = smb.NewConnection(*self.options.smbOptions)
	if err != nil {
		self.println(err)
		self.options.c = nil
		return
	}
	self.printf("Connected to %s:%d\n", host, port)
}

func (self *shell) closeConnection() {
	if self.authenticated {
		self.logout()
	}
	self.options.c.Close()
	self.options.c = nil
	return
}

func (self *shell) closeConnectionFunc(argArr interface{}) {
	if self.options.c == nil {
		self.println("No connection open")
		return
	}
	self.closeConnection()
	return
}

func (self *shell) executeLogin() {
	err := self.options.c.SessionSetup()
	if err != nil {
		self.println(err)
		return
	}
	self.authenticated = true
	self.printf("[+] Login successful as %s\n", self.options.c.GetAuthUsername())
	return
}

func (self *shell) loginFunc(argArr interface{}) {
	if self.options.c == nil {
		self.println("Open a connection before attempting to login")
		return
	}

	err := self.logout()
	if err != nil {
		self.println(err)
		return
	}

	args := argArr.([]string)
	if len(args) < 1 {
		err = self.options.c.SetInitiator(&smb.NTLMInitiator{
			NullSession: true,
		})
	} else {
		userdomain := args[0]
		domain := ""
		username := ""
		localUser := false
		parts := strings.Split(userdomain, "/")
		if len(parts) > 1 {
			domain = parts[0]
			username = parts[1]
		} else {
			username = parts[0]
			localUser = true
		}

		pass := ""
		if len(args) > 1 {
			pass = args[1]
		} else {
			self.printf("Enter password: ")
			passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
			self.println()
			if err != nil {
				self.println(err)
				return
			}
			pass = string(passBytes)
		}

		err = self.options.c.SetInitiator(&smb.NTLMInitiator{
			User:      username,
			Password:  pass,
			Domain:    domain,
			LocalUser: localUser,
		})
	}

	if err != nil {
		self.println(err)
		return
	}

	self.executeLogin()
}

func (self *shell) loginHashFunc(argArr interface{}) {
	if self.options.c == nil {
		self.println("Open a connection before attempting to login")
		return
	}

	err := self.logout()
	if err != nil {
		self.println(err)
		return
	}

	args := argArr.([]string)
	if len(args) < 1 {
		err = self.options.c.SetInitiator(&smb.NTLMInitiator{
			NullSession: true,
		})
	} else {
		userdomain := args[0]
		domain := ""
		username := ""
		localUser := false
		parts := strings.Split(userdomain, "/")
		if len(parts) > 1 {
			domain = parts[0]
			username = parts[1]
		} else {
			username = parts[0]
			localUser = true
		}

		var hashBytes []byte
		var hash string

		if len(args) > 1 {
			hash = args[1]
		} else {
			self.printf("Enter NT Hash (hex): ")
			hashStringBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
			self.println()
			if err != nil {
				self.println(err)
				return
			}
			hash = string(hashStringBytes)
		}
		hashBytes, err = hex.DecodeString(hash)
		if err != nil {
			self.println(err)
			return
		}

		err = self.options.c.SetInitiator(&smb.NTLMInitiator{
			User:      username,
			Hash:      hashBytes,
			Domain:    domain,
			LocalUser: localUser,
		})
	}

	if err != nil {
		self.println(err)
		return
	}

	self.executeLogin()
}

func (self *shell) logout() error {
	if !self.authenticated {
		return nil
	}
	self.share = ""
	self.rcwd = ""
	self.lcwd = ""
	self.authenticated = false
	return self.options.c.Logoff()
}

func (self *shell) logoutFunc(argArr interface{}) {
	if !self.authenticated {
		self.println("Not logged in!")
		return
	}
	if self.options.c == nil {
		return
	}
	self.logout()
	return
}

func (self *shell) cmdloop() {
	fmt.Println("Welcome to the interactive shell!\nType 'help' for a list of commands")
	if useRawTerminal {
		// Unfortunately we can't capture signals like ctrl-c or ctrl-d in RawMode
		oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
		if err != nil {
			self.println(err)
			return
		}
		defer term.Restore(int(os.Stdin.Fd()), oldState)
	}

	self.t = term.NewTerminal(os.Stdin, self.prompt)
	// Disable logging from smb library as it interferes with the terminal emulation output
	golog.Set("github.com/jfjallid/go-smb/gss", "gss", golog.LevelNone, 0, golog.NoOutput, golog.NoOutput)
	golog.Set("github.com/jfjallid/go-smb/smb", "smb", golog.LevelNone, 0, golog.NoOutput, golog.NoOutput)
	golog.Set("github.com/jfjallid/go-smb/smb/dcerpc", "dcerpc", golog.LevelNone, 0, golog.NoOutput, golog.NoOutput)

OuterLoop:
	for {
		input, err := self.t.ReadLine()
		if err != nil {
			if err == io.EOF {
				break OuterLoop
			}
			self.printf("Error reading from stdin: %s\n", err)
			return
		}
		if strings.Compare(input, "exit") == 0 {
			break OuterLoop
		}
		parts := strings.Split(input, " ")
		cmd := input
		args := []string{}
		if len(parts) > 1 {
			cmd = strings.ToLower(parts[0])
			args = parts[1:]
		} else {
			cmd = strings.ToLower(cmd)
		}

		if val, ok := handlers[cmd]; ok {
			fn := val.(func(interface{}))
			log.Debugf("Running command: (%s)\n", input)
			fn(args)
		} else if cmd != "" {
			self.printf("Unknown command: (%s)\n", input)
		}
	}
	self.t.SetPrompt("")
	self.println("Bye!")
}
