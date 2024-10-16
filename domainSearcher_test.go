package main

import (
	"bufio"
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/cloudflare-go"
	"github.com/fatih/color"
	_ "github.com/mattn/go-sqlite3"
	"github.com/ovh/go-ovh/ovh"
	"github.com/oze4/godaddygo"
	"github.com/twiny/whois/v2"
)

// Test checkFileExists
func TestCheckFileExists(t *testing.T) {
	// Create temp file
	tmpfile, err := os.CreateTemp("", "example")
	if err != nil {
		t.Fatal(err)
	}
	// Remove test file en end of test function execution
	defer os.Remove(tmpfile.Name())

	// Check file exists
	if !checkFileExists(tmpfile.Name()) {
		t.Fatalf("Expected file %s to exist, but it does not", tmpfile.Name())
	}

	// Check inexistent file exists
	if checkFileExists("nonexistentfile.txt") {
		t.Fatalf("Expected nonexistentfile.txt to not exist, but it does")
	}
}

// Test checkDNS
func TestCheckDNS(t *testing.T) {
	// Valid domain
	validDomain := "alfaexploit.com"
	if err := checkDNS(validDomain); err != nil {
		t.Errorf("Expected domain %s to be valid, but got error: %v", validDomain, err)
	}

	// Empty domain
	invalidDomain := ""
	if err := checkDNS(invalidDomain); err == nil {
		t.Errorf("Expected domain %s to be invalid, but got no error", invalidDomain)
	}

	// len(name) > 255 domain
	invalidDomain = "KpYTnQSWGuQ5pm4bQyx9rluKU4q8qLj1QNTd4wcT4OzBgJwQo1BGskbctE1mabrGOUCESgFBeTqEHVbhXEVDJM4rgR56CXDFoWTPIwlM9MTMR09B3fwkUY4GzO2bl35cMpVRL1cYcNJMU98oh0l7KBiBzA6eKHkXdoagQbuuT1KS4OovGAa5JH2TxmbEPSGynT2p3JhDTGVm0ZHRfBly5HharptauKdqVNeZegzlVofJ4D1FxpjOBzqSAeO1VAs.com"
	if err := checkDNS(invalidDomain); err == nil {
		t.Errorf("Expected domain %s to be invalid, but got no error", invalidDomain)
	}

	// Invalid domains
	invalidDomain = "ex*ample.com"
	if err := checkDNS(invalidDomain); err == nil {
		t.Errorf("Expected domain %s to be invalid, but got no error", invalidDomain)
	}

	invalidDomain = ".example.com"
	if err := checkDNS(invalidDomain); err == nil {
		t.Errorf("Expected domain %s to be invalid, but got no error", invalidDomain)
	}

	invalidDomain = "-example.com"
	if err := checkDNS(invalidDomain); err == nil {
		t.Errorf("Expected domain %s to be invalid, but got no error", invalidDomain)
	}

	invalidDomain = "example.com-"
	if err := checkDNS(invalidDomain); err == nil {
		t.Errorf("Expected domain %s to be invalid, but got no error", invalidDomain)
	}

	invalidDomain = "ex~ample.com-"
	if err := checkDNS(invalidDomain); err == nil {
		t.Errorf("Expected domain %s to be invalid, but got no error", invalidDomain)
	}
}

// Test createTable
func TestCreateTable(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Errorf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Create table
	err = createTable(db)
	if err != nil {
		t.Errorf("Expected no error, but got: %v", err)
	}

	// Check if table exists
	_, err = db.Exec("SELECT 1 FROM domain_list LIMIT 1;")
	if err != nil {
		t.Errorf("Expected table domain_list to exist, but got error: %v", err)
	}
}

func TestPopulateOvh(t *testing.T) {
	// Copy original functions content
	getOvhDomainsOri := getOvhDomains
	// unmock functions content
	defer func() {
		getOvhDomains = getOvhDomainsOri
	}()

	getOvhDomains = func(client *ovh.Client, OVHDomainData *[]string) error {
		*OVHDomainData = append(*OVHDomainData, "testdomain1.com")
		return nil
	}

	// Create memory database
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Create table
	err = createTable(db)
	if err != nil {
		t.Fatalf("Failed to create table: %v", err)
	}

	if err := populateOvh(db); err != nil {
		t.Errorf("Expected no error when checking populateOvh, but got: %v", err)
	}
}

func TestPopulateCloudFlare(t *testing.T) {
	// Copy original functions content
	getCloudFlareDomainsOri := getCloudFlareDomains
	// unmock functions content
	defer func() {
		getCloudFlareDomains = getCloudFlareDomainsOri
	}()

	getCloudFlareDomains = func(api *cloudflare.API) ([]cloudflare.Zone, error) {

		zone := cloudflare.Zone{
			ID:                "1234567890abcdef1234567890abcdef",
			Name:              "example.com",
			DevMode:           0,
			OriginalNS:        []string{"ns1.example.com", "ns2.example.com"},
			OriginalRegistrar: "Example Registrar",
			OriginalDNSHost:   "Example DNS Host",
			CreatedOn:         time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
			ModifiedOn:        time.Date(2023, 1, 2, 12, 0, 0, 0, time.UTC),
			NameServers:       []string{"ns-cloud-a1.googledomains.com", "ns-cloud-a2.googledomains.com"},
			Owner: cloudflare.Owner{
				ID:        "owner123",
				Email:     "owner@example.com",
				Name:      "Example Owner",
				OwnerType: "user",
			},
			Permissions: []string{
				"#dns_records:edit",
				"#dns_records:read",
			},
			Plan: cloudflare.ZonePlan{
				ZonePlanCommon: cloudflare.ZonePlanCommon{
					ID:        "free",
					Name:      "Free Plan",
					Price:     0,
					Currency:  "USD",
					Frequency: "monthly",
				},
				LegacyID:          "legacy123",
				IsSubscribed:      true,
				CanSubscribe:      true,
				LegacyDiscount:    false,
				ExternallyManaged: false,
			},
			PlanPending: cloudflare.ZonePlan{
				ZonePlanCommon: cloudflare.ZonePlanCommon{
					ID:        "",
					Name:      "",
					Price:     0,
					Currency:  "",
					Frequency: "",
				},
				LegacyID:          "",
				IsSubscribed:      false,
				CanSubscribe:      false,
				LegacyDiscount:    false,
				ExternallyManaged: false,
			},
			Status: "active",
			Paused: false,
			Type:   "full",
			Host: struct {
				Name    string
				Website string
			}{
				Name:    "Example Host",
				Website: "https://www.example.com",
			},
			VanityNS:    nil,
			Betas:       nil,
			DeactReason: "",
			Meta: cloudflare.ZoneMeta{
				PageRuleQuota:     3,
				WildcardProxiable: false,
				PhishingDetected:  false,
			},
			Account: cloudflare.Account{
				ID:        "account123",
				Name:      "Example Account",
				Type:      "standard",
				CreatedOn: time.Date(2022, 12, 25, 10, 0, 0, 0, time.UTC),
				Settings:  nil,
			},
			VerificationKey: "verificationkey123",
		}

		zones := []cloudflare.Zone{zone}
		return zones, nil
	}

	// Create memory database
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Create table
	err = createTable(db)
	if err != nil {
		t.Fatalf("Failed to create table: %v", err)
	}

	if err := populateCloudFlare(db); err != nil {
		t.Errorf("Expected no error when checking populateCloudFlare, but got: %v", err)
	}
}

func TestPopulateGoDaddy(t *testing.T) {
	// Copy original functions content
	getGoDaddyDomainsOri := getGoDaddyDomains
	// unmock functions content
	defer func() {
		getGoDaddyDomains = getGoDaddyDomainsOri
	}()

	getGoDaddyDomains = func(api godaddygo.API) ([]godaddygo.DomainSummary, error) {
		expiration, _ := time.Parse(time.RFC3339, "2025-01-01T00:00:00Z")
		created, _ := time.Parse(time.RFC3339, "2020-01-01T00:00:00Z")

		zone := godaddygo.DomainSummary{
			Domain:    "example.com",
			Status:    "ACTIVE",
			Expires:   expiration,
			CreatedAt: created,
		}

		zones := []godaddygo.DomainSummary{zone}
		return zones, nil
	}

	// Create memory database
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Create table
	err = createTable(db)
	if err != nil {
		t.Fatalf("Failed to create table: %v", err)
	}

	if err := populateGoDaddy(db); err != nil {
		t.Errorf("Expected no error when checking populateGoDaddy, but got: %v", err)
	}
}

// populateDonDominio(db)
func TestPopulateDonDominio(t *testing.T) {
	// Copy original functions content
	getDonDominioDomainsOri := getDonDominioDomains
	// unmock functions content
	defer func() {
		getDonDominioDomains = getDonDominioDomainsOri
	}()

	getDonDominioDomains = func(client *http.Client, r *http.Request) (*http.Response, error) {
		//fmt.Println("-- Executing mocked getDonDominioDomains function")
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

		responseData := Response{
			Success:      true,
			ErrorCode:    0,
			ErrorCodeMsg: "",
			Action:       "domain/list",
			Version:      "1.0.20",
			ResponseData: ResponseData{
				QueryInfo: QueryInfo{
					Page:       1,
					PageLength: 1000,
					Results:    122,
					Total:      122,
				},
				Domains: []Domain{
					{
						Name:     "example.com",
						Status:   "active",
						TLD:      "com",
						DomainID: 123456,
						TsExpir:  "2025-01-01",
					},
				},
			},
		}

		responseJSON, _ := json.Marshal(responseData)

		resp := &http.Response{
			StatusCode: 200,
			Body:       ioutil.NopCloser(bytes.NewBuffer(responseJSON)),
			Header:     make(http.Header),
		}

		// Configurar encabezados HTTP si es necesario
		resp.Header.Set("Content-Type", "application/json")
		return resp, nil
	}

	// Create memory database
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Create table
	err = createTable(db)
	if err != nil {
		t.Fatalf("Failed to create table: %v", err)
	}

	if err := populateDonDominio(db, "nil"); err != nil {
		t.Errorf("Expected no error when checking populateDonDominio, but got: %v", err)
	}
}

// Test populateDB
func TestPopulateDB(t *testing.T) {
	// Copy original functions content
	populateOvhOri := populateOvh
	populateCloudFlareOri := populateCloudFlare
	populateGoDaddyOri := populateGoDaddy
	populateDonDominioOri := populateDonDominio
	// unmock functions content
	defer func() {
		populateOvh = populateOvhOri
		populateCloudFlare = populateCloudFlareOri
		populateGoDaddy = populateGoDaddyOri
		populateDonDominio = populateDonDominioOri
	}()

	populateOvh = func(db *sql.DB) error {
		return nil
	}
	populateCloudFlare = func(db *sql.DB) error {
		return nil
	}
	populateGoDaddy = func(db *sql.DB) error {
		return nil
	}
	populateDonDominio = func(db *sql.DB, socks5 string) error {
		return nil
	}

	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Errorf("Failed to open database: %v", err)
	}
	defer db.Close()

	if err := populateDB(db, "nil"); err != nil {
		t.Errorf("Expected no error when populating db, but got: %v", err)
	}

	populateOvh = func(db *sql.DB) error {
		return errors.New("populateOvh error")
	}
	populateCloudFlare = func(db *sql.DB) error {
		return errors.New("populateCloudFlare error")
	}
	populateGoDaddy = func(db *sql.DB) error {
		return errors.New("populateGoDaddy error")
	}
	populateDonDominio = func(db *sql.DB, socks5 string) error {
		return errors.New("populateDonDominio error")
	}

	if err := populateDB(db, "nil"); err == nil {
		t.Errorf("Expected error when populating db, but got: %v", err)
	}
}

// Test getDnsNs
func TestGetDnsNs(t *testing.T) {
	ns, err := getDnsNs("alfaexploit.com")
	if err != nil {
		t.Errorf("Expected no error in getDnsNs, but got: %v", err)
	} else {
		for _, v := range ns {
			//fmt.Println("  ", v.Host)
			if v.Host != "dns200.anycast.me." && v.Host != "ns200.anycast.me." {
				t.Errorf("Expected dns200.anycast.me or ns200.anycast.me, but got: %v", v.Host)
			}
		}
	}
}

// Test getWhois
func TestGetWhois(t *testing.T) {
	_, err := getWhois("alfaexploit.com")
	if err != nil {
		t.Errorf("Expected no error in getWhois, but got: %v", err)
	}
}

// Test queryDB
func TestQueryDB(t *testing.T) {
	// Mock getDnsNs function in order to speed up tests execution
	getDnsNsOri := getDnsNs
	// unmock functions content
	defer func() {
		getDnsNs = getDnsNsOri
	}()

	getDnsNs = func(domainToSearch string) ([]*net.NS, error) {
		//fmt.Println("-- Executing mocked getDnsNs function, domain: ", domainToSearch)
		switch domainToSearch {
		case "alfaexploit.com":
			ns := make([]*net.NS, 2)
			ns[0] = &net.NS{
				Host: "nstest1.example.com.",
			}
			ns[1] = &net.NS{
				Host: "nstest2.example.com.",
			}
			return ns, nil
		default:
			return nil, nil
		}
	}

	// Mock getWhois function in order to speed up tests execution
	getWhoisOri := getWhois
	// unmock functions content
	defer func() {
		getWhois = getWhoisOri
	}()

	getWhois = func(domainToSearch string) (whois.Response, error) {
		//fmt.Println("-- Executing mocked getWhois function, domain: ", domainToSearch)
		return whois.Response{
			Domain:    domainToSearch,
			Name:      domainToSearch,
			TLD:       "test",
			WHOISHost: "whois.test.com",
			WHOISRaw:  "testWHOIS",
		}, nil
	}

	// Create memory database
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Create table
	err = createTable(db)
	if err != nil {
		t.Fatalf("Failed to create table: %v", err)
	}

	// Insert test domain
	_, err = db.Exec(`INSERT INTO domain_list (id, realId, isp, domain) VALUES ("1", "realId", "ovh", "example.com")`)
	if err != nil {
		t.Fatalf("Failed to insert domain: %v", err)
	}

	// Search domain
	err = queryDB("example.com", db)
	if err != nil {
		t.Errorf("Expected no error when querying existing domain, but got: %v", err)
	}

	// Search non-db domain
	err = queryDB("alfaexploit.com", db)
	if err != nil {
		t.Errorf("Expected no error when querying non-db domain, but got: %v", err)
	}

	// Search inexistent domain
	err = queryDB("nonexistent.com", db)
	if err != nil {
		t.Errorf("Expected no error when querying nonexistent domain, but got: %v", err)
	}
}

// Test checkPopulatedDb
func TestCheckPopulateDB(t *testing.T) {
	// Create memory database
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Create table
	err = createTable(db)
	if err != nil {
		t.Fatalf("Failed to create table: %v", err)
	}

	// Insert test domain
	_, err = db.Exec(`INSERT INTO domain_list (id, realId, isp, domain) VALUES ("1", "realId", "ovh", "example.com")`)
	if err != nil {
		t.Fatalf("Failed to insert domain: %v", err)
	}

	// Search inexistent domain
	err = checkPopulatedDb(db)
	if err != nil {
		t.Errorf("Expected no error when checking databse population, but got: %v", err)
	}
}

// Test regenerateDb
func TestRegenerateDb(t *testing.T) {
	// Copy original functions content
	populateOvhOri := populateOvh
	populateCloudFlareOri := populateCloudFlare
	populateGoDaddyOri := populateGoDaddy
	populateDonDominioOri := populateDonDominio
	checkPopulatedDbOri := checkPopulatedDb
	// unmock functions content
	defer func() {
		populateOvh = populateOvhOri
		populateCloudFlare = populateCloudFlareOri
		populateGoDaddy = populateGoDaddyOri
		populateDonDominio = populateDonDominioOri
		checkPopulatedDb = checkPopulatedDbOri
	}()

	populateOvh = func(db *sql.DB) error {
		return nil
	}
	populateCloudFlare = func(db *sql.DB) error {
		return nil
	}
	populateGoDaddy = func(db *sql.DB) error {
		return nil
	}
	populateDonDominio = func(db *sql.DB, socks5 string) error {
		return nil
	}
	checkPopulatedDb = func(db *sql.DB) error {
		return nil
	}

	dbFile := "/tmp/testDb.db"
	if err := regenerateDb(dbFile, "nil"); err != nil {
		t.Errorf("Expected no error when checking TestRegenerateDb, but got: %v", err)
	}

	checkPopulatedDb = func(db *sql.DB) error {
		return fmt.Errorf("Error populating DB")
	}
	if err := regenerateDb(dbFile, "nil"); err == nil {
		t.Errorf("Expected error when checking TestRegenerateDb, but got: %v", err)
	}

}

// Test main
func TestMain(t *testing.T) {
	// Copy original functions content
	populateOvhOri := populateOvh
	populateCloudFlareOri := populateCloudFlare
	populateGoDaddyOri := populateGoDaddy
	populateDonDominioOri := populateDonDominio
	// unmock functions content
	defer func() {
		populateOvh = populateOvhOri
		populateCloudFlare = populateCloudFlareOri
		populateGoDaddy = populateGoDaddyOri
		populateDonDominio = populateDonDominioOri
	}()

	populateOvh = func(db *sql.DB) error {
		return nil
	}
	populateCloudFlare = func(db *sql.DB) error {
		return nil
	}
	populateGoDaddy = func(db *sql.DB) error {
		return nil
	}
	populateDonDominio = func(db *sql.DB, socks5 string) error {
		return nil
	}
	checkPopulatedDb = func(db *sql.DB) error {
		return nil
	}

	// Save original Args and restore on exit function
	oldArgs := os.Args
	defer func() {
		os.Args = oldArgs
	}()

	// Args reset
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	// Configure new Args
	os.Args = []string{"cmd", "-exit"}

	// Copy original functions content
	// We cant unmock it using defer because maybe we need to make some prints in console for debugging
	osStdoutOri := os.Stdout
	osStderrOri := os.Stderr
	colorOutputOri := color.Output
	colorErrorOri := color.Error

	// All content written to w pipe, will be copied automatically to r pipe
	r, w, _ := os.Pipe()
	// Make Stdout/Stderr to be written to w pipe
	// Color module defines other Stdout/Stderr, so pipe them to w pipe too
	os.Stdout = w
	os.Stderr = w
	color.Output = w
	color.Error = w

	main()

	// Close w pipe
	w.Close()

	// Restore Stdout/Stderr to normal output
	os.Stdout = osStdoutOri
	os.Stderr = osStderrOri
	color.Output = colorOutputOri
	color.Error = colorErrorOri

	// Read all r pipe content
	out, _ := io.ReadAll(r)
	//fmt.Println("--- out ---")
	//fmt.Println(out)

	scanner := bufio.NewScanner(bytes.NewReader(out))
	bannerFound := false
	for scanner.Scan() {
		line := scanner.Text()
		//fmt.Println("-- LINE: ", line)
		if strings.Contains(line, "coded by Kr0m: alfaexploit.com") {
			bannerFound = true
			break
		}
	}

	if !bannerFound {
		t.Fatalf(`TestMain: No banner found`)
	}
}

// Test main -regenerateDB
func TestMainDbFileRegenerateDB(t *testing.T) {
	dbFile := "/tmp/testDb.db"

	// Remove DB:
	err := os.Remove(dbFile)
	fileNotFoundError := "remove " + dbFile + ": no such file or directory"
	if err != nil && err.Error() != fileNotFoundError {
		t.Fatalf(`Error deleting DB file: %s`, dbFile)
	}

	// Create DB:
	file, err := os.Create(dbFile)
	if err != nil {
		t.Fatalf(`Error TestMainDbFileRegenerateDB: %v`, err)
	}
	file.Close()

	// Copy original functions content
	populateOvhOri := populateOvh
	populateCloudFlareOri := populateCloudFlare
	populateGoDaddyOri := populateGoDaddy
	populateDonDominioOri := populateDonDominio
	// unmock functions content
	defer func() {
		populateOvh = populateOvhOri
		populateCloudFlare = populateCloudFlareOri
		populateGoDaddy = populateGoDaddyOri
		populateDonDominio = populateDonDominioOri
	}()

	populateOvh = func(db *sql.DB) error {
		return nil
	}
	populateCloudFlare = func(db *sql.DB) error {
		return nil
	}
	populateGoDaddy = func(db *sql.DB) error {
		return nil
	}
	populateDonDominio = func(db *sql.DB, socks5 string) error {
		return nil
	}
	checkPopulatedDb = func(db *sql.DB) error {
		return nil
	}

	// Save original Args and restore on exit function
	oldArgs := os.Args
	defer func() {
		os.Args = oldArgs
	}()

	// Args reset
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	// Configure new Args
	os.Args = []string{"cmd", "-regenerateDB", "-exit"}

	// Copy original functions content
	// We cant unmock it using defer because maybe we need to make some prints in console for debugging
	osStdoutOri := os.Stdout
	osStderrOri := os.Stderr
	colorOutputOri := color.Output
	colorErrorOri := color.Error

	// All content written to w pipe, will be copied automatically to r pipe
	r, w, _ := os.Pipe()

	// Make Stdout/Stderr to be written to w pipe
	// Color module defines other Stdout/Stderr, so pipe them to w pipe too
	os.Stdout = w
	os.Stderr = w
	color.Output = w
	color.Error = w

	main()

	// Close w pipe
	w.Close()

	// Restore Stdout/Stderr to normal output
	os.Stdout = osStdoutOri
	os.Stderr = osStderrOri
	color.Output = colorOutputOri
	color.Error = colorErrorOri

	// Read all r pipe content
	out, _ := io.ReadAll(r)
	//fmt.Println("--- out ---")
	//fmt.Println(out)

	scanner := bufio.NewScanner(bytes.NewReader(out))
	lineFound := false
	for scanner.Scan() {
		line := scanner.Text()
		//fmt.Println("-- LINE: ", line)
		if strings.Contains(line, "> Regenerating DB.") {
			lineFound = true
			break
		}
	}

	if !lineFound {
		t.Fatalf(`TestMainDbFileRegenerateDB: '> Regenerating DB.' line not found`)
	}
}

// Test searchCLI correct query
func TestSearchCLICorrectQuery(t *testing.T) {
	// Args reset
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	// Create memory database
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Create table
	err = createTable(db)
	if err != nil {
		t.Fatalf("Failed to create table: %v", err)
	}

	// Insert test domain
	_, err = db.Exec(`INSERT INTO domain_list (id, realId, isp, domain) VALUES ("1", "realId", "ovh", "example.com")`)
	if err != nil {
		t.Fatalf("Failed to insert domain: %v", err)
	}

	// Save original os.Stdout, os.Stderr
	osStdoutOri := os.Stdout
	osStderrOri := os.Stderr
	colorOutputOri := color.Output
	colorErrorOri := color.Error

	// Create pipes for capturing output and simulating input
	// In a pipe what is written to its w extreme can be readed on its r extreme
	rOut, wOut, _ := os.Pipe()
	rIn, wIn, _ := os.Pipe()

	// Redirect os.Stdout and os.Stderr -> wOut
	os.Stdout = wOut
	os.Stderr = wOut
	color.Output = wOut
	color.Error = wOut

	// Simulate user input by writing to wIn
	input := "example.com\n"
	io.WriteString(wIn, input)
	wIn.Close() // Close input after writing

	// Run the search function, readline in searchCLI function doesnt read fro STDIN, it reads from console directly, thats the reason we send the STDIN to read from
	searchCLI(db, true, io.NopCloser(rIn))

	// Close the write end of the output pipe to signal that we are done writing
	wOut.Close()

	// Restore os.Stdout and os.Stderr to their original state
	os.Stdout = osStdoutOri
	os.Stderr = osStderrOri
	color.Output = colorOutputOri
	color.Error = colorErrorOri

	// Read the captured output from the pipe
	out, err := io.ReadAll(rOut)
	if err != nil {
		t.Fatalf("Failed to read output: %v", err)
	}

	// Scan output and check if expected line is present
	scanner := bufio.NewScanner(bytes.NewReader(out))
	lineFound := false
	for scanner.Scan() {
		line := scanner.Text()
		//fmt.Println("LINE: ", line) // Depuración
		if strings.Contains(line, "DOMAIN: example.com") {
			lineFound = true
			break
		}
	}

	if !lineFound {
		t.Fatalf(`TestSearchCLICorrectQuery: 'DOMAIN: example.com' line not found`)
	}
}

// Test searchCLI incorrect query1
func TestSearchCLIIncorrectQuery1(t *testing.T) {
	// Args reset
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	// Create memory database
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Create table
	err = createTable(db)
	if err != nil {
		t.Fatalf("Failed to create table: %v", err)
	}

	// Insert test domain
	_, err = db.Exec(`INSERT INTO domain_list (id, realId, isp, domain) VALUES ("1", "realId", "ovh", "example.com")`)
	if err != nil {
		t.Fatalf("Failed to insert domain: %v", err)
	}

	// Save original os.Stdout, os.Stderr
	osStdoutOri := os.Stdout
	osStderrOri := os.Stderr
	colorOutputOri := color.Output
	colorErrorOri := color.Error

	// Create pipes for capturing output and simulating input
	// In a pipe what is written to its w extreme can be readed on its r extreme
	rOut, wOut, _ := os.Pipe()
	rIn, wIn, _ := os.Pipe()

	// Redirect os.Stdout and os.Stderr -> wOut
	os.Stdout = wOut
	os.Stderr = wOut
	color.Output = wOut
	color.Error = wOut

	// Simulate user input by writing to the input pipe
	input := "KpYTnQSWGuQ5pm4bQyx9rluKU4q8qLj1QNTd4wcT4OzBgJwQo1BGskbctE1mabrGOUCESgFBeTqEHVbhXEVDJM4rgR56CXDFoWTPIwlM9MTMR09B3fwkUY4GzO2bl35cMpVRL1cYcNJMU98oh0l7KBiBzA6eKHkXdoagQbuuT1KS4OovGAa5JH2TxmbEPSGynT2p3JhDTGVm0ZHRfBly5HharptauKdqVNeZegzlVofJ4D1FxpjOBzqSAeO1VAs.com\n"
	io.WriteString(wIn, input)
	wIn.Close()

	// Run the search function, readline in searchCLI function doesnt read fro STDIN, it reads from console directly, thats the reason we send the STDIN to read from
	searchCLI(db, true, io.NopCloser(rIn))

	// Close output pipe to signal that we are done writing
	wOut.Close()

	// Restore os.Stdout and os.Stderr to their original state
	os.Stdout = osStdoutOri
	os.Stderr = osStderrOri
	color.Output = colorOutputOri
	color.Error = colorErrorOri

	// Read all output
	out, _ := io.ReadAll(rOut)
	if err != nil {
		t.Fatalf("Failed to read output: %v", err)
	}

	// Scan output and check if expected line is present
	scanner := bufio.NewScanner(bytes.NewReader(out))
	lineFound := false
	for scanner.Scan() {
		line := scanner.Text()
		//fmt.Println("LINE: ", line)
		if strings.Contains(line, "Invalid domain") {
			lineFound = true
			break
		}
	}

	if !lineFound {
		t.Fatalf(`TestSearchCLIIncorrectQuery1: 'Invalid domain' line not found`)
	}
}

// Test searchCLI incorrect query2
func TestSearchCLIIncorrectQuery2(t *testing.T) {
	// Args reset
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	// Create memory database
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Create table
	err = createTable(db)
	if err != nil {
		t.Fatalf("Failed to create table: %v", err)
	}

	// Insert test domain
	_, err = db.Exec(`INSERT INTO domain_list (id, realId, isp, domain) VALUES ("1", "realId", "ovh", "example.com")`)
	if err != nil {
		t.Fatalf("Failed to insert domain: %v", err)
	}

	// Save original os.Stdout, os.Stderr
	osStdoutOri := os.Stdout
	osStderrOri := os.Stderr
	colorOutputOri := color.Output
	colorErrorOri := color.Error

	// Create pipes for capturing output and simulating input
	// In a pipe what is written to its w extreme can be readed on its r extreme
	rOut, wOut, _ := os.Pipe()
	rIn, wIn, _ := os.Pipe()

	// Redirect os.Stdout and os.Stderr -> wOut
	os.Stdout = wOut
	os.Stderr = wOut
	color.Output = wOut
	color.Error = wOut

	// Simulate user input by writing to the input pipe
	input := "*.asd.com\n"
	io.WriteString(wIn, input)
	wIn.Close()

	// Run the search function, readline in searchCLI function doesnt read fro STDIN, it reads from console directly, thats the reason we send the STDIN to read from
	searchCLI(db, true, io.NopCloser(rIn))

	// Close output pipe to signal that we are done writing
	wOut.Close()

	// Restore os.Stdout and os.Stderr to their original state
	os.Stdout = osStdoutOri
	os.Stderr = osStderrOri
	color.Output = colorOutputOri
	color.Error = colorErrorOri

	// Read all output
	out, _ := io.ReadAll(rOut)
	if err != nil {
		t.Fatalf("Failed to read output: %v", err)
	}

	// Scan output and check if expected line is present
	scanner := bufio.NewScanner(bytes.NewReader(out))
	lineFound := false
	for scanner.Scan() {
		line := scanner.Text()
		//fmt.Println("LINE: ", line)
		if strings.Contains(line, "Invalid domain") {
			lineFound = true
			break
		}
	}

	if !lineFound {
		t.Fatalf(`TestSearchCLIIncorrectQuery2: 'Invalid domain' line not found`)
	}
}
