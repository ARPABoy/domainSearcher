#### OVH-Cloudflare-GoDaddy-DonDominio NS/Whois search system

OVH-Cloudflare-GoDaddy-DonDominio NS/Whois search system with sqlite cache support.

First step to be taken before program execution is to create creds directory with the following content:
```
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
```

You can get available command line options via:
```
go run domainSearcher.go -h
```

Bear in mind that DonDominio requires IP authorization in order to query API service, so execute program from allowed systems only or you will get errors.

Also you can check unitary tests running:
```
go test
```
