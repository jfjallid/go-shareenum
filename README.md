# go-ShareEnum

## Description
Package go-shareenum is a tool build to enumerate SMB shares in a Windows
domain. It is built on top of the library https://github.com/jfjallid/go-smb
and provides functionality to list SMB shares and enumerate the files.

## Usage
```
Usage: ./go-shareenum [options]

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
```

## Examples


### List SMB Shares

```
./go-shareenum --host server001 --user Administrator --pass adminPass123 --enum
```

### List SMB Shares and specify password on command line

```
./go-shareenum --host server001 --user Administrator --enum
```

### List files of the shares named "backup" and "files"

```
./go-shareenum --host server001 --user Administrator --pass adminPass123 --shares backup,files --list
```

### List files of all the shares recursively but exclude C$ and ADMIN$

```
./go-shareenum --host server001 --user Administrator --pass adminPass123 --enum --recurse --list --exclude "ADMIN$,C$"
```
