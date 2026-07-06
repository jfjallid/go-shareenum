# go-ShareEnum

## Description
Package go-shareenum is a tool build to enumerate SMB shares in a Windows
domain. It is built on top of the library [go-smb](https://github.com/jfjallid/go-smb)
and provides functionality to list SMB shares and enumerate the files.

## Usage
```
Usage: ./go-shareenum [options]

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

### Start an interactive session

```
./go-shareenum --host server001 --user Administrator --pass adminPass123 --interactive
```

### Upload a local file to a share

```
./go-shareenum --host server001 --user Administrator --pass adminPass123 --shares backup --put-file --local-file ./report.txt --remote-path "\reports\report.txt"
```

### Download a single file from a share

Saves to the remote filename in the current directory when --local-file is omitted:

```
./go-shareenum --host server001 --user Administrator --pass adminPass123 --shares backup --get-file --remote-path "\reports\report.txt"
```

Or to an explicit local path (use --replace to overwrite an existing local file):

```
./go-shareenum --host server001 --user Administrator --pass adminPass123 --shares backup --get-file --remote-path "\reports\report.txt" --local-file ./report.txt --replace
```
