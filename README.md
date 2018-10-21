[![Build Status](https://travis-ci.org/adedayo/sshscan.svg?branch=master)](https://travis-ci.org/adedayo/sshscan)

# SSHscan 
SSHscan is a simple utility for inspecting or auditing an SSH server for various settings such as supported encryption and key exchange algorithms.

## Using sshscan as a library
In order to start, go get this repository:
```go
go get github.com/adedayo/sshscan
```

### Example
In your code simply import as usual and enjoy:

```go
package main

import 
(
    "fmt"
    "github.com/adedayo/sshscan"
)

func main() {
	scan := sshscan.Inspect("host", "22")
	fmt.Printf("%#v\n", scan)
}
```
This should produce an output similar to the following:
```
sshscan.SSHExchange{ProtocolVersion:"SSH-2.0-OpenSSH_7.6p1 Ubuntu-4\r\n", Cookie:[16]uint8{0x9e, 0x37, 0xe0, 0x10, 0xf0, 0x28, 0x5d,0xf9, 0x7c, 0x31, 0xb6, 0xb5, 0x84, 0xb, 0xf4, 0xa4}, KEXAlgorithms:[]string{"ssh-rsa", "rsa-sha2-512", "rsa-sha2-256", "ecdsa-sha2-nistp256", "ssh-ed25519"}, ServerHostKeyAlgos:[]string{"chacha20-poly1305@openssh.com", "aes128-ctr", "aes192-ctr", "aes256-ctr", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com"}, EncAlgosC2S:[]string{"chacha20-poly1305@openssh.com", "aes128-ctr", "aes192-ctr", "aes256-ctr", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com"}, EncAlgosS2C:[]string{"umac-64-etm@openssh.com", "umac-128-etm@openssh.com", "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com", "hmac-sha1-etm@openssh.com", "umac-64@openssh.com", "umac-128@openssh.com", "hmac-sha2-256", "hmac-sha2-512", "hmac-sha1"}, MACAlgosC2S:[]string{"umac-64-etm@openssh.com", "umac-128-etm@openssh.com", "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com", "hmac-sha1-etm@openssh.com", "umac-64@openssh.com", "umac-128@openssh.com", "hmac-sha2-256", "hmac-sha2-512", "hmac-sha1"}, MACAlgosS2C:[]string{"none", "zlib@openssh.com"}, CompAlgosC2S:[]string{"none", "zlib@openssh.com"}, CompAlgosS2C:[]string{""}, LanguagesC2S:[]string{""}, LanguagesS2C:[]string{""}, Fail:false, FailReason:""}
```

## Using it as a command-line tool
sshscan is also available as a command-line tool. 

### Installation
Prebuilt binaries may be found for your operating system here: https://github.com/adedayo/sshscan/releases

For macOS X, you could install via brew as follows:
```bash
brew tap adedayo/tap
brew install sshscan
``` 

### Inspecting a server

```bash
#scan on the default port 22
sshscan host

#specify port explicitly
sshscan -p 22222 host
```

For JSON-formatted output simply add the `--json` or `-j` flag:

```bash
sshscan --json host
```

## License
BSD 3-Clause License