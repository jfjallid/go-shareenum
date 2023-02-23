# go-ShareEnum

## Description
Package go-shareenum is a tool build to enumerate SMB shares in a Windows
domain. It is built on top of the library https://github.com/jfjallid/go-smb
and provides functionality to list SMB shares and enumerate the files.

## Usage
```
Usage of ./go-shareenum:
  -d string
    	domain
  -debug
    	enable debugging
  -enum
    	List available SMB shares
  -exshare string
    	Comma-separated list of shares to exclude
  -hash string
    	hex encoded NT Hash for user
  -host string
    	host
  -list
    	Perform directory listing of shares
  -noenc
    	disable smb encryption
  -pass string
    	password
  -port int
    	SMB Port (default 445)
  -recurse
    	Recursively list directories on server
  -shares string
    	Comma-separated list of shares to connect to
  -smb2
    	Force smb 2.1
  -user string
    	username
```

## Examples


### List SMB Shares

```
./go-shareenum --host server001 -user Administrator -pass adminPass123 -enum
```

### List SMB Shares and specify password on command line

```
./go-shareenum --host server001 -user Administrator -enum
```

### List files of the shares named "backup" and "files"

```
./go-shareenum --host server001 -user Administrator -pass adminPass123 -shares backup,files -list
```

### List files of all the shares recursively but exclude C$ and ADMIN$

```
./go-shareenum --host server001 -user Administrator -pass adminPass123 -enum -recurse -list -exshare "ADMIN$,C$"
```
