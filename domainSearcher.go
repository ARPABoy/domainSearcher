package main

// OVH-Cloudflare-GoDaddy-DonDominio NS/Whois search system
// TODO: Inline search domain editing
// TODO: ProxySocks5 support for domain scraping

// go get github.com/ovh/go-ovh/ovh
// go get github.com/inancgumus/screen
// go get github.com/mattn/go-sqlite3
// go get github.com/fatih/color
// go get github.com/cloudflare/cloudflare-go
// go get github.com/oze4/godaddygo
// go get github.com/twiny/whois/v2
// go get github.com/davecgh/go-spew/spew

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/cloudflare/cloudflare-go"
	"github.com/fatih/color"
	"github.com/inancgumus/screen"
	_ "github.com/mattn/go-sqlite3"
	"github.com/ovh/go-ovh/ovh"
	"github.com/oze4/godaddygo"
	"github.com/twiny/whois/v2"
	"golang.org/x/net/proxy"
	// "github.com/davecgh/go-spew/spew"
)

func checkFileExists(filePath string) bool {
	_, error := os.Stat(filePath)
	return !errors.Is(error, os.ErrNotExist)
}

// Check valid DNS
func checkDNS(name string) error {
	switch {
	case len(name) == 0:
		return errors.New("Domain name is empty")
	case len(name) > 255:
		return fmt.Errorf("Domain name length is %d, can't exceed 255", len(name))
	}
	var l int
	for i := 0; i < len(name); i++ {
		b := name[i]
		if b == '.' {
			// check domain labels validity
			switch {
			case i == l:
				return fmt.Errorf("Domain has invalid character '.' at offset %d, label can't begin with a period", i)
			case i-l > 63:
				return fmt.Errorf("Domain byte length of label '%s' is %d, can't exceed 63", name[l:i], i-l)
			case name[l] == '-':
				return fmt.Errorf("Domain label '%s' at offset %d begins with a hyphen", name[l:i], l)
			case name[i-1] == '-':
				return fmt.Errorf("Domain label '%s' at offset %d ends with a hyphen", name[l:i], l)
			}
			l = i + 1
			continue
		}
		// test label character validity, note: tests are ordered by decreasing validity frequency
		if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b >= 'A' && b <= 'Z') {
			// show the printable unicode character starting at byte offset i
			c, _ := utf8.DecodeRuneInString(name[i:])
			if c == utf8.RuneError {
				return fmt.Errorf("Domain has invalid rune at offset %d", i)
			}
			return fmt.Errorf("Domain has invalid character '%c' at offset %d", c, i)
		}
	}

	// check top level domain validity
	switch {
	case l == len(name):
		return fmt.Errorf("Domain has missing top level domain, domain can't end with a period")
	case len(name)-l > 63:
		return fmt.Errorf("Domain's top level domain '%s' has byte length %d, can't exceed 63", name[l:], len(name)-l)
	case name[l] == '-':
		return fmt.Errorf("Domain's top level domain '%s' at offset %d begin with a hyphen", name[l:], l)
	case name[len(name)-1] == '-':
		return fmt.Errorf("Domain's top level domain '%s' at offset %d ends with a hyphen", name[l:], l)
	case name[l] >= '0' && name[l] <= '9':
		return fmt.Errorf("Domain's top level domain '%s' at offset %d begins with a digit", name[l:], l)
	}
	return nil
}

func createTable(db *sql.DB) error {
	// Set default font color:
	color.Set(color.FgCyan)

	createTableSQL := `CREATE TABLE IF NOT EXISTS domain_list ( "id" VARCHAR(100), "realId" VARCHAR(100), "isp" VARCHAR(100), "domain" VARCHAR(100));`
	statement, err := db.Prepare(createTableSQL)
	if err != nil {
		color.Red("++ ERROR: %s", err)
		// Set default font color:
		color.Set(color.FgCyan)
		return err
	}
	statement.Exec()
	//log.Println(">> domain_list table created")

	return nil
}

var getOvhDomains = func(client *ovh.Client, OVHDomainData *[]string) error {
	if err := client.Get("/domain", &OVHDomainData); err != nil {
		return err
	}
	return nil
}

var populateOvh = func(db *sql.DB) error {
	fmt.Println()
	fmt.Println("- Getting OVH data:")
	ovhIdsFile := "configs/ovh.list"
	if _, err := os.Stat(ovhIdsFile); err != nil {
		color.Red("++ ERROR: File does not exist: %s", ovhIdsFile)
		color.Red("   Create it with the following content syntax:")
		color.Red("   ovhId:ovhKey:ovhSecret:ovhConsumer:ovhRealId")
		// Set default font color:
		color.Set(color.FgCyan)
		return err
	} else {
		file, err := os.Open(ovhIdsFile)
		if err != nil {
			color.Red("++ ERROR: %s", err)
			// Set default font color:
			color.Set(color.FgCyan)
			return err
		}

		insertSQL := `INSERT INTO domain_list(id, realId, isp, domain) VALUES (?, ?, ?, ?)`
		statement, err := db.Prepare(insertSQL)
		if err != nil {
			color.Red("++ ERROR: %s", err)
			// Set default font color:
			color.Set(color.FgCyan)
			return err
		}

		// Parse IDs config file:
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			// If API access fails, color configuration is lost, reassign in each iteration
			color.Set(color.FgCyan)
			//fmt.Println(scanner.Text())
			dataFields := strings.Split(scanner.Text(), ":")
			//fmt.Println(dataFields)
			ovhId := dataFields[0]
			// Check comment line
			if ovhId[0:1] == "#" {
				continue
			}
			ovhKey := dataFields[1]
			ovhSecret := dataFields[2]
			ovhConsumer := dataFields[3]
			ovhRealId := dataFields[4]
			fmt.Println("-- ovhId:", ovhId)
			//fmt.Println("ovhKey:", ovhKey)
			//fmt.Println("ovhSecret:", ovhSecret)
			//fmt.Println("ovhConsumer:", ovhConsumer)
			//fmt.Println("ovhRealId:", ovhRealId)
			client, _ := ovh.NewClient(
				"ovh-eu",
				ovhKey,
				ovhSecret,
				ovhConsumer,
			)

			// Query OVH API:
			OVHDomainData := []string{}
			// client.Get wrapped in order to be able to mock it
			//if err := client.Get("/domain", &OVHDomainData); err != nil {
			if err := getOvhDomains(client, &OVHDomainData); err != nil {
				color.Red("++ ERROR: %s", err)
				// Set default font color:
				color.Set(color.FgCyan)
				continue
			}
			//fmt.Println("OVHDomainData: ", OVHDomainData)

			// Insert retrieved information to DB:
			for i := 0; i < len(OVHDomainData); i++ {
				//fmt.Printf("Inserting ID: %s RealID: %s, ISP: %s Domain: %s.\n", ovhId, ovhRealId, "ovh", OVHDomainData[i])
				_, err = statement.Exec(ovhId, ovhRealId, "ovh", OVHDomainData[i])
				if err != nil {
					color.Red("++ ERROR: %s", err)
					// Set default font color:
					color.Set(color.FgCyan)
					return err
				}
			}
		}

		if err := scanner.Err(); err != nil {
			color.Red("++ ERROR: %s", err)
			// Set default font color:
			color.Set(color.FgCyan)
			return err
		}
	}
	return nil
}

var getCloudFlareDomains = func(api *cloudflare.API) ([]cloudflare.Zone, error) {
	zones, err := api.ListZones(context.Background())
	if err != nil {
		return nil, err
	}
	return zones, err
}

var populateCloudFlare = func(db *sql.DB) error {
	fmt.Println()
	fmt.Println("- Getting Cloudflare data:")
	cloudflareIdsFile := "configs/cloudflare.list"
	if _, err := os.Stat(cloudflareIdsFile); err != nil {
		color.Red("++ ERROR: File does not exist: %s", cloudflareIdsFile)
		color.Red("   Create it with the following content syntax:")
		color.Red("   email:password")
		// Set default font color:
		color.Set(color.FgCyan)
		return err
	} else {
		file, err := os.Open(cloudflareIdsFile)
		if err != nil {
			color.Red("++ ERROR: %s", err)
			// Set default font color:
			color.Set(color.FgCyan)
			return err
		}

		insertSQL := `INSERT INTO domain_list(id, realId, isp, domain) VALUES (?, ?, ?, ?)`
		statement, err := db.Prepare(insertSQL)
		if err != nil {
			color.Red("++ ERROR: %s", err)
			// Set default font color:
			color.Set(color.FgCyan)
			return err
		}

		// Parse IDs config file:
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			// If API access fails, color configuration is lost, reassign in each iteration
			color.Set(color.FgCyan)
			//fmt.Println(scanner.Text())
			dataFields := strings.Split(scanner.Text(), ":")
			//fmt.Println(dataFields)
			cloudflareEmail := dataFields[0]
			// Check comment line
			if cloudflareEmail[0:1] == "#" {
				continue
			}
			cloudflareApiKey := dataFields[1]
			fmt.Println("-- cloudflareEmail:", cloudflareEmail)
			//fmt.Println("cloudflareApiKey:", cloudflareApiKey)

			api, err := cloudflare.New(cloudflareApiKey, cloudflareEmail)
			if err != nil {
				color.Red("++ ERROR: %s", err)
				// Set default font color:
				color.Set(color.FgCyan)
				continue
			}

			// Fetch all zones available to this user.
			//zones, err := api.ListZones(context.Background())
			zones, err := getCloudFlareDomains(api)
			if err != nil {
				color.Red("++ ERROR: %s", err)
				// Set default font color:
				color.Set(color.FgCyan)
				continue
			}

			for _, z := range zones {
				//fmt.Println(z.Name)
				_, err = statement.Exec(cloudflareEmail, cloudflareEmail, "cloudflare", z.Name)
				if err != nil {
					color.Red("++ ERROR: %s", err)
					// Set default font color:
					color.Set(color.FgCyan)
					return err
				}
			}
		}

		if err := scanner.Err(); err != nil {
			color.Red("++ ERROR: %s", err)
			// Set default font color:
			color.Set(color.FgCyan)
			return err
		}
	}
	return nil
}

var getGoDaddyDomains = func(api godaddygo.API) ([]godaddygo.DomainSummary, error) {
	godaddy := api.V1()
	zones, err := godaddy.ListDomains(context.Background())
	if err != nil {
		return nil, err
	}
	//spew.Dump(zones)
	return zones, err
}

var populateGoDaddy = func(db *sql.DB) error {
	fmt.Println()
	fmt.Println("- Getting GoDaddy data:")
	godaddyIdsFile := "configs/godaddy.list"
	if _, err := os.Stat(godaddyIdsFile); err != nil {
		color.Red("++ ERROR: File does not exist: %s", godaddyIdsFile)
		color.Red("   Create it with the following content syntax:")
		color.Red("   ID:key:secret")
		// Set default font color:
		color.Set(color.FgCyan)
		return err
	} else {
		file, err := os.Open(godaddyIdsFile)
		if err != nil {
			color.Red("++ ERROR: %s", err)
			// Set default font color:
			color.Set(color.FgCyan)
			return err
		}

		insertSQL := `INSERT INTO domain_list(id, realId, isp, domain) VALUES (?, ?, ?, ?)`
		statement, err := db.Prepare(insertSQL)
		if err != nil {
			color.Red("++ ERROR: %s", err)
			// Set default font color:
			color.Set(color.FgCyan)
			return err
		}

		// Parse IDs config file:
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			// If API access fails, color configuration is lost, reassign in each iteration
			color.Set(color.FgCyan)
			//fmt.Println(scanner.Text())
			dataFields := strings.Split(scanner.Text(), ":")
			//fmt.Println(dataFields)
			godaddyId := dataFields[0]
			// Check comment line
			if godaddyId[0:1] == "#" {
				continue
			}
			godaddyKey := dataFields[1]
			godaddySecret := dataFields[2]
			godaddyRealId := dataFields[3]
			fmt.Println("-- godaddyId:", godaddyId)
			//fmt.Println("godaddyKey:", godaddyKey)
			//fmt.Println("godaddySecret:", godaddySecret)
			//fmt.Println("godaddyRealId:", godaddyRealId)

			api, err := godaddygo.NewProduction(godaddyKey, godaddySecret)
			if err != nil {
				color.Red("++ ERROR: %s", err)
				// Set default font color:
				color.Set(color.FgCyan)
				continue
			}
			//spew.Dump(api)
			//godaddy := api.V1()

			// Fetch all zones available to this user.
			//zones, err := godaddy.ListDomains(context.Background())
			zones, err := getGoDaddyDomains(api)
			//spew.Dump(zones)
			if err != nil {
				color.Red("++ ERROR: %s", err)
				// Set default font color:
				color.Set(color.FgCyan)
				continue
			}

			for _, z := range zones {
				//fmt.Println(z.Domain)
				_, err = statement.Exec(godaddyId, godaddyRealId, "godaddy", z.Domain)
				if err != nil {
					color.Red("++ ERROR: %s", err)
					// Set default font color:
					color.Set(color.FgCyan)
					return err
				}
			}
		}

		if err := scanner.Err(); err != nil {
			color.Red("++ ERROR: %s", err)
			// Set default font color:
			color.Set(color.FgCyan)
			return err
		}
	}
	return nil
}

var getDonDominioDomains = func(client *http.Client, r *http.Request) (*http.Response, error) {
	resp, err := client.Do(r)
	if err != nil {
		return resp, err
	}
	return resp, nil
}

var populateDonDominio = func(db *sql.DB, socks5 string) error {
	// curl -d "apiuser=USERNAME&apipasswd=PASSWORD" -H "Content-Type: application/x-www-form-urlencoded" -X POST https://simple-api.dondominio.net/tool/hello/|jq
	// DonDominio requires IP-API whitelisting
	fmt.Println()
	fmt.Println("- Getting DonDominio data:")
	donDominioIdsFile := "configs/donDominio.list"
	if _, err := os.Stat(donDominioIdsFile); err != nil {
		color.Red("++ ERROR: File does not exist: %s", donDominioIdsFile)
		color.Red("   Create it with the following content syntax:")
		color.Red("   id:user:pass")
		// Set default font color:
		color.Set(color.FgCyan)
		return err
	} else {
		file, err := os.Open(donDominioIdsFile)
		if err != nil {
			color.Red("++ ERROR: %s", err)
			// Set default font color:
			color.Set(color.FgCyan)
			return err
		}

		insertSQL := `INSERT INTO domain_list(id, realId, isp, domain) VALUES (?, ?, ?, ?)`
		statement, err := db.Prepare(insertSQL)
		if err != nil {
			color.Red("++ ERROR: %s", err)
			// Set default font color:
			color.Set(color.FgCyan)
			return err
		}

		// Parse IDs config file:
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			// If API access fails, color configuration is lost, reassign in each iteration
			color.Set(color.FgCyan)
			//fmt.Println(scanner.Text())
			dataFields := strings.Split(scanner.Text(), ":")
			//fmt.Println(dataFields)
			donDominioId := dataFields[0]
			// Check comment line
			if donDominioId[0:1] == "#" {
				continue
			}
			donDominioUser := dataFields[1]
			donDominioPass := dataFields[2]
			//fmt.Println("donDominioId: ", donDominioId)
			fmt.Println("-- donDominioId:", donDominioId)
			//fmt.Println("donDominioUser: ", donDominioUser)
			//fmt.Println("donDominioPass: ", donDominioPass)

			client := &http.Client{}
			if socks5 != "nil" {
				socks5Proxy := socks5
				dialer, err := proxy.SOCKS5("tcp", socks5Proxy, nil, proxy.Direct)
				if err != nil {
					color.Red("++ ERROR: Unable to connect to SOCKS5 proxy: %v", err)
					return err
				}

				transport := &http.Transport{
					Dial: dialer.Dial,
				}

				client = &http.Client{
					Transport: transport,
				}
			}

			apiUrl := "https://simple-api.dondominio.net"
			resource := "/domain/list/"
			//resource := "/tool/hello/"
			data := url.Values{}
			data.Set("apiuser", donDominioUser)
			data.Set("apipasswd", donDominioPass)

			u, _ := url.ParseRequestURI(apiUrl)
			u.Path = resource
			// "https://simple-api.dondominio.net/domain/list/"
			urlStr := u.String()

			//spew.Dump(client)
			r, _ := http.NewRequest(http.MethodPost, urlStr, strings.NewReader(data.Encode()))
			r.Header.Add("Content-Type", "application/x-www-form-urlencoded")

			if resp, err := getDonDominioDomains(client, r); err != nil {
				//if resp, err := client.Do(r); err != nil {
				color.Red("++ ERROR populateDonDominio: %s", err)
				// Set default font color:
				color.Set(color.FgCyan)
				continue
			} else {
				// Define json structs
				type QueryInfo struct {
					Page       int `json:"page"`
					PageLength int `json:"pageLength"`
					Results    int `json:"results"`
					Total      int `json:"total"`
				}

				type Domain struct {
					Name     string `json:"name"`
					Status   string `json:"status"`
					TLD      string `json:"tld"`
					DomainID int    `json:"domainID"`
					TsExpir  string `json:"tsExpir"`
				}

				type ResponseData struct {
					QueryInfo QueryInfo `json:"queryInfo"`
					Domains   []Domain  `json:"domains"`
				}

				type Response struct {
					Success      bool         `json:"success"`
					ErrorCode    int          `json:"errorCode"`
					ErrorCodeMsg string       `json:"errorCodeMsg"`
					Action       string       `json:"action"`
					Version      string       `json:"version"`
					ResponseData ResponseData `json:"responseData"`
				}

				//fmt.Println(resp.Status)
				respBody, _ := ioutil.ReadAll(resp.Body)
				//fmt.Println(string(respBody))

				var response Response
				err := json.Unmarshal([]byte(string(respBody)), &response)
				if err != nil {
					color.Red("Error deserializing JSON, continuing: %v -> %v", err, string(respBody))
					continue
				}

				for _, domain := range response.ResponseData.Domains {
					//fmt.Println("Domain:", domain.Name)
					_, err = statement.Exec(donDominioId, donDominioUser, "dondominio", domain.Name)
					if err != nil {
						color.Red("++ ERROR: %v", err)
						// Set default font color:
						color.Set(color.FgCyan)
						return err
					}
				}
			}
		}

		if err := scanner.Err(); err != nil {
			color.Red("++ ERROR: %s", err)
			// Set default font color:
			color.Set(color.FgCyan)
			return err
		}
	}
	return nil
}

func populateDB(db *sql.DB, socks5 string) error {
	// Set default font color:
	color.Set(color.FgCyan)

	populatingError := false

	fmt.Println("> Populating DB")

	if err := populateOvh(db); err != nil {
		//color.Red("++ ERROR populateOvh: %s", err)
		populatingError = true
	}

	if err := populateCloudFlare(db); err != nil {
		//color.Red("++ ERROR populateCloudFlare: %s", err)
		populatingError = true
	}

	if err := populateGoDaddy(db); err != nil {
		//color.Red("++ ERROR populateGoDaddy: %s", err)
		populatingError = true
	}

	if err := populateDonDominio(db, socks5); err != nil {
		//color.Red("++ ERROR populateDonDominio: %s", err)
		populatingError = true
	}

	// If API access fails, color configuration is lost
	color.Set(color.FgCyan)
	fmt.Println("> Done")

	if populatingError {
		return fmt.Errorf("Error populating DB")
	}
	return nil
}

var getDnsNs = func(domainToSearch string) ([]*net.NS, error) {
	ns, err := net.LookupNS(domainToSearch)
	return ns, err
}

var getWhois = func(domainToSearch string) (whois.Response, error) {
	var whoisResponse whois.Response
	if client, err := whois.NewClient(nil); err != nil {
		return whoisResponse, err
	} else {
		resp, err := client.Query(context.TODO(), domainToSearch)
		return resp, err
	}
}

func queryDB(domainToSearch string, db *sql.DB) error {
	// Set default font color:
	color.Set(color.FgCyan)

	//fmt.Println("domainToSearch: ", domainToSearch)

	// Check if domain related row exists:
	row, err := db.Query("SELECT COUNT(*) FROM domain_list WHERE domain=?", domainToSearch)
	if err != nil {
		color.Red("++ ERROR: %s", err)
		// Set default font color:
		color.Set(color.FgCyan)
		return err
	}
	defer row.Close()

	for row.Next() {
		var n int
		row.Scan(&n)
		//fmt.Printf("N: %d\n", n)
		if n == 0 {
			color.Yellow("  NOT FOUND")

			// NS lookup:
			ns, err := getDnsNs(domainToSearch)
			if err != nil {
				color.Red("++ ERROR NS: Couldnt query NS servers: %s", err)
				// Set default font color:
				color.Set(color.FgCyan)
			} else {
				color.Set(color.FgCyan)
				fmt.Println("------------")
				color.Yellow("  NS servers:")
				for _, v := range ns {
					color.Set(color.FgGreen)
					fmt.Println("  ", v.Host)
				}
			}

			// WHOIS lookup
			resp, err := getWhois(domainToSearch)
			if err != nil {
				color.Red("++ ERROR WHOIS: %s", err)
				// Set default font color:
				color.Set(color.FgCyan)
			} else {
				// Print the response
				color.Set(color.FgCyan)
				fmt.Println("------------")
				color.Yellow("  WHOIS Info:")
				color.Set(color.FgGreen)
				fmt.Printf("%+v\n", resp)
				color.Set(color.FgCyan)
				fmt.Println("------------")
			}

			fmt.Println("")
			return nil
		}
	}

	// Query DB for domain data:
	row, err = db.Query("SELECT * FROM domain_list WHERE domain=?", domainToSearch)
	if err != nil {
		color.Red("++ ERROR: %s", err)
		// Set default font color:
		color.Set(color.FgCyan)
		return err
	}
	defer row.Close()

	fmt.Println("------------")
	for row.Next() {
		var id string
		var realId string
		var isp string
		var domain string
		row.Scan(&id, &realId, &isp, &domain)
		color.Green("  ID: %s\n", id)
		color.Green("  REALID: %s\n", realId)
		color.Green("  ISP: %s\n", isp)
		color.Green("  DOMAIN: %s\n", domain)
		color.Set(color.FgCyan)
		fmt.Println("------------")
	}

	fmt.Println("")
	return nil
}

var checkPopulatedDb = func(db *sql.DB) error {
	// Set default font color:
	color.Set(color.FgCyan)

	row, err := db.Query("SELECT COUNT(*) FROM domain_list")
	if err != nil {
		color.Red("++ ERROR: %s", err)
		// Set default font color:
		color.Set(color.FgCyan)
		return err
	}
	defer row.Close()

	for row.Next() {
		var n int
		row.Scan(&n)
		//fmt.Printf("N: %d\n", n)
		if n == 0 {
			return fmt.Errorf("Error: DB not populated")
		}
	}
	return nil
}

func regenerateDb(dbFile, socks5 string) error {
	//fmt.Println("Executing: regenerateDb")

	// Remove DB:
	err := os.Remove(dbFile)
	fileNotFoundError := "remove " + dbFile + ": no such file or directory"
	if err != nil && err.Error() != fileNotFoundError {
		color.Red("++ ERROR: %s", err)
		// Set default font color:
		color.Set(color.FgCyan)
		return err
	}

	// Create DB:
	file, err := os.Create(dbFile)
	if err != nil {
		color.Red("++ ERROR: %s", err)
		// Set default font color:
		color.Set(color.FgCyan)
		return err
	} else {
		fmt.Println("> DB file created successfully")
	}
	file.Close()

	// Open DB:
	var sqliteDatabase *sql.DB
	if sqliteDatabase, err = sql.Open("sqlite3", dbFile); err != nil {
		color.Red("++ ERROR: regenerateDb Error opening DB file: %s", err)
		// Set default font color:
		color.Set(color.FgCyan)
		return err
	}
	defer sqliteDatabase.Close()

	// Create table:
	if err := createTable(sqliteDatabase); err != nil {
		color.Red("++ ERROR creating DB table")
		// Set default font color:
		color.Set(color.FgCyan)
		return err
	} else {
		fmt.Println("> DB table created successfully")
	}

	// Populate DB:
	if err := populateDB(sqliteDatabase, socks5); err != nil {
		color.Red("++ ERROR populating DB")
		// Set default font color:
		color.Set(color.FgCyan)
		return err
	} else {
		if err := checkPopulatedDb(sqliteDatabase); err != nil {
			color.Red("++ ERROR: Empty DB or not populated correctly")
			// Set default font color:
			color.Set(color.FgCyan)
			return err
		} else {
			fmt.Println("> DB populated successfully")
		}
	}
	return nil
}

func searchCLI(db *sql.DB, oneSearch bool) {
	// Search domain:
	fmt.Println("")
	var domainToSearch string
	for {
		// Fix: Strange behaviour related to colors when returning from queryDB function, this color reassigment fixes it
		color.Set(color.FgCyan)
		fmt.Printf("> Domain to search: ")
		color.Set(color.FgWhite)
		fmt.Scanln(&domainToSearch)
		color.Set(color.FgCyan)
		// Check correct domain syntax
		//fmt.Printf("domainToSearch: %s\n", domainToSearch)
		//fmt.Printf("len(domainToSearch): %i\n", len(domainToSearch))
		if domainToSearch != "" {
			if len(domainToSearch) < 100 {
				if err := checkDNS(domainToSearch); err != nil {
					//fmt.Printf("err: %v\n", err)
					color.Yellow("  Invalid domain")
				} else {
					//fmt.Printf("err: %v\n", err)
					if err := queryDB(domainToSearch, db); err != nil {
						color.Red("++ ERROR: %s", err)
						// Set default font color:
						color.Set(color.FgCyan)
					}
				}
				domainToSearch = ""
			} else {
				color.Yellow("  Invalid domain")
			}
		}
		if oneSearch {
			return
		}
	}
}

func main() {
	dbFile := "domain_list.db"

	// Set default font color:
	color.Set(color.FgCyan)

	//fmt.Print("\033[H\033[2J")
	// Portable clear screen version
	screen.MoveTopLeft()
	screen.Clear()
	fmt.Println("######################################################################################")
	fmt.Println("| OVH-Cloudflare-GoDaddy-DonDominio(SOCKS-5) NS/Whois search system: Ctrl+c -> Exit  |")
	fmt.Printf("| v0.8-sqlite: %s - coded by Kr0m: alfaexploit.com                       |\n", dbFile)
	fmt.Println("######################################################################################")
	fmt.Println("")

	// -regenerateDB command:
	regenerateDBPtr := flag.Bool("regenerateDB", false, "Force DB regeneration.")
	// -socks5 command:
	socks5Ptr := flag.String("socks5", "", "Use socks5 proxy only for DonDominio scraping.")
	exitPtr := flag.Bool("exit", false, "Exit without waiting for user input, useful combined with -regenerateDB. Also useful for unit-testing.")
	flag.Parse()
	//fmt.Println("regenerateDB:", *regenerateDBPtr)
	//fmt.Println("socks5:", *socks5Ptr)
	//fmt.Println("exit:", *exitPtr)

	socks5 := "nil"
	if *socks5Ptr != "" {
		socks5 = *socks5Ptr
	}

	fmt.Printf("> Checking if previous %s file exists\n", dbFile)
	sqliteBbExists := checkFileExists(dbFile)
	if sqliteBbExists {
		fmt.Printf("  DB: %s FOUND\n", dbFile)
		// Regenerate DB arg:
		if *regenerateDBPtr {
			fmt.Println("> Regenerating DB.")
			if err := regenerateDb(dbFile, socks5); err != nil {
				os.Exit(1)
			}

			// Exit arg
			if *exitPtr {
				return
			}
		} else {
			// Open DB:
			var sqliteDatabase *sql.DB
			var err error
			if sqliteDatabase, err = sql.Open("sqlite3", dbFile); err != nil {
				color.Red("++ ERROR: main Error opening DB file: %s", err)
				os.Exit(1)
			}
			defer sqliteDatabase.Close()

			// Check if DB is populated
			if err := checkPopulatedDb(sqliteDatabase); err != nil {
				fmt.Println("> DB is not populated")
				if err := regenerateDb(dbFile, socks5); err != nil {
					os.Exit(1)
				}
			}

			// Exit arg
			if *exitPtr {
				return
			}
		}
	} else {
		fmt.Printf("  DB: %s file NOT FOUND, creating it\n", dbFile)
		if err := regenerateDb(dbFile, socks5); err != nil {
			os.Exit(1)
		}

		// Exit arg
		if *exitPtr {
			return
		}
	}

	// Open DB:
	var sqliteDatabase *sql.DB
	var err error
	if sqliteDatabase, err = sql.Open("sqlite3", dbFile); err != nil {
		color.Red("++ ERROR: main2 Error opening DB file: %s", err)
		os.Exit(1)
	}
	defer sqliteDatabase.Close()
	searchCLI(sqliteDatabase, false)
}
