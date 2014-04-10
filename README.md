# coronary
![](http://share.amerine.net/heartbleed.png)

Tests CIDR blocks for OpenSSL [CVE-2014-0160][CVE] aka [Heartbleed][heartbleed].

Inspired by Jonathan Rudenberg's [heartbleeder][heartbleeder].

## Using

```shell
$ coronary 192.168.1.0/24
Scanning: 192.168.1.11/22
VULNERABLE - 192.168.1.71:443 has the heartbeat extension enabled and is vulnerable to CVE-2014-0160
SECURE - 192.168.1.119:443 does not have the heartbeat extension enabled
VULNERABLE - 192.168.1.72:443 has the heartbeat extension enabled and is vulnerable to CVE-2014-0160
VULNERABLE - 192.168.1.142:443 has the heartbeat extension enabled and is vulnerable to CVE-2014-0160
SECURE - 192.168.1.180:443 does not have the heartbeat extension enabled

```

## Installation

Build from the source using `go get` (e.g. `go get github.com/amerine/coronary`)

[CVE]: https://www.openssl.org/news/secadv_20140407.txt
[heartbleed]: http://heartbleed.com/
[heartbleeder]: https://github.com/titanous/heartbleeder
