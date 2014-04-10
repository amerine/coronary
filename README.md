# Coronary

Tests CIDR blocks for OpenSSL [CVE-2014-0160][CVE] aka [Heartbleed][heartbleed].

Inspired by Jonathan Rudenberg's [heartbleeder][heartbleeder].

## Using

```shell
coronary 192.168.1.0/24
```

## Installation

Build from the source using `go get` (e.g. `go get github.com/amerine/coronary`)

[CVE]: https://www.openssl.org/news/secadv_20140407.txt
[heartbleed]: http://heartbleed.com/
[heartbleeder]: https://github.com/titanous/heartbleeder
