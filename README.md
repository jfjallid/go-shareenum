# go-ShareEnum

## Description
Package go-shareenum is a tool build to enumerate SMB shares in a Windows
domain. It is built on top of the library [go-smb](https://github.com/jfjallid/go-smb)
and provides functionality to list SMB shares and enumerate the files.

## Usage
```
Usage: ./go-shareenum [options]

options:
      --host                Hostname or ip address of remote server
  -P, --port                SMB Port (default 445)
  -d, --domain              Domain name to use for login
  -u, --user                Username
  -p, --pass                Password
  -n, --no-pass             Disable password prompt and send no credentials
      --hash                Hex encoded NT Hash for user password
      --local               Authenticate as a local user instead of domain user
      --null	            Attempt null session authentication
  -t, --timeout             Dial timeout in seconds (default 5)
      --enum                List available SMB shares
      --exclude             Comma-separated list of shares to exclude
      --list                Perform directory listing of shares
      --shares              Comma-separated list of shares to connect to
      --include-name        Regular expression filter for files to include in the result
      --include-exts        Comma-separated list of file extensions to include in the result.
                            Mutually exclusive with exclude-ext
      --exclude-exts        Comma-separated list of file extensions to exclude from the result.
                            Mutually exclusive with include-ext
      --exclude-folders     Comma-separated list of folders to not traverse with recursion
      --min-size            Minimum file size to include in results in bytes
      --download <outdir>   Attempt to download all the files in the filtered result set.
  -r, --recurse             Recursively list directories on server
      --relay               Start an SMB listener that will relay incoming
                            NTLM authentications to the remote server and
                            use that connection. NOTE that this forces SMB 2.1
                            without encryption.
      --relay-port <port>   Listening port for relay (default 445)
      --socks-host <target> Establish connection via a SOCKS5 proxy server
      --socks-port <port>   SOCKS5 proxy port (default 1080)
      --noenc               Disable smb encryption
      --smb2                Force smb 2.1
      --debug               Enable debug logging
      --verbose             Enable verbose logging
  -v, --version             Show version
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
