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
