#### OVH-Cloudflare-GoDaddy-DonDominio NS/Whois search system.
OVH-Cloudflare-GoDaddy-DonDominio NS/Whois search system with sqlite as cache.

## Table of contents
- [Initial configuration](#initial-configuration)
- [CLI parameters](#cli-parameters)

---

## Initial configuration:

```
git clone https://github.com/ARPABoy/domainSearcher.git
```

First step to be taken before program execution is to create creds directory with the following content:
```
cd domainSearcher
mkdir configs
```

```
vi configs/cloudflare.list
EMAIL:APIKEY

vi configs/donDominio.list
NAME:ID:PASS

vi configs/godaddy.list
NAME:KEY:SECRET:ID

vi configs/ovh.list
NAME:KEY:SECRET:CONSUMER:ID
```

Then:
```
go mod tidy
go build
./domainSearcher
```

---

## CLI parameters:

You can get available command line options via:
```
go run domainSearcher.go -h
```

Bear in mind that DonDominio requires IP authorization in order to query API service, so execute program from allowed systems or use -regenerateDB and -socks5 flag combination.
```
ssh USER@ALLOWED_HOST -pPORT -D 7777 -N -f
go run domainSearcher.go -regenerateDB -socks5 localhost:7777
```

Regenerate DB and make a query:
```
go run domainSearcher.go -regenerateDB
```

Regenerate DB and exit:
```
go run domainSearcher.go -regenerateDB -exit
```

Fast domain checking:
```
go run domainSearcher.go alfaexploit.com
```

Also you can check unitary tests running:
```
go test
go test -coverprofile=coverage.out && go tool cover -func=coverage.out
```

---

Software provided by kr0m(ARPABoy): https://alfaexploit.com
