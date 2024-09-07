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

***configs/cloudflare.list:***
```
EMAIL:APIKEY
```

***configs/donDominio.list:***
```
NAME:ID:PASS
```

***configs/godaddy.list:***
```
NAME:KEY:SECRET:ID
```

***configs/ovh.list:***
```
NAME:KEY:SECRET:CONSUMER:ID
```

Then:
```
go mod tidy
go build
./domainSearcher
```

---

## CLI parameters

You can get available command line options via:
```
go run domainSearcher.go -h
```

Bear in mind that DonDominio requires IP authorization in order to query API service, so execute program from allowed systems only or you will get errors.

Also you can check unitary tests running:
```
go test
go test -coverprofile=coverage.out && go tool cover -func=coverage.out
```

---

Software provided by kr0m(ARPABoy): https://alfaexploit.com
