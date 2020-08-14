package nessus

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/buger/jsonparser"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"text/template"
	"time"
)

// struct which stores relevant nessus config information
type Nessus struct {
	Username   string
	Password   string
	Url        string
	Token      string
	ApiKey     string
	HttpClient *http.Client
}

// Config struct used to render scanner templates
type config struct {
	Name    string
	Targets string
}

// Gets nessus credentials from environment
func (n *Nessus) EnvCredentials() {
	n.Username = os.Getenv("NESSUS_USERNAME")
	n.Password = os.Getenv("NESSUS_PASSWORD")
}

// Sets nessus credentials manually
func (n *Nessus) Credentials(username string, password string) {
	n.Username = username
	n.Password = password
}

// Creates new nessus client for the provided url
func NewNessus(url string) Nessus {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	nessus := Nessus{
		Username:   "",
		Password:   "",
		Url:        url,
		Token:      "",
		ApiKey:     "",
		HttpClient: client,
	}

	nessus.GetApiKey()
	return nessus
}

// Retrieves the nessus API key from the nessus6.js file
func (n *Nessus) GetApiKey() {
	resp, err := n.HttpClient.Get(n.Url + "/nessus6.js")
	regex := regexp.MustCompile(`(?m)[0-9A-F]{8}\-[0-9A-F]{4}\-4[0-9A-F]{3}\-[89AB][0-9A-F]{3}\-[0-9A-F]{12}`)

	if err != nil {
		log.Fatal(err)
	}

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		log.Fatal(err)
	}

	apiKey := regex.FindString(string(body))

	n.ApiKey = apiKey
}

// Logs into nessus using the credentials set either manually or from the environment
func (n *Nessus) Authenticate() {
	values := map[string]string{
		"username": n.Username,
		"password": n.Password,
	}

	jsonValues, _ := json.Marshal(values)

	resp, err := n.HttpClient.Post(n.Url+"/session", "application/json", bytes.NewBuffer(jsonValues))

	if err != nil {
		log.Fatal(err)
	}

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		log.Fatal(err)
	}

	token, err := jsonparser.GetString(body, "token")

	if err != nil {
		log.Fatal("Authention Failure")
	}

	n.Token = token
}

// Waits for the specified scan to finish
func (n *Nessus) Wait(scanId int) error {
	req, err := http.NewRequest("GET", n.Url+fmt.Sprintf("/scans/%d", scanId), nil)

	if err != nil {
		log.Fatal(err)
	}

	req.Header.Set("X-Cookie", "token="+n.Token)
	req.Header.Set("X-API-Token", n.ApiKey)
	req.Header.Set("Content-Type", "application/json")

	for {
		resp, err := n.HttpClient.Do(req)
		if err != nil {
			return err
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		status, err := jsonparser.GetString(body, "status")
		if err != nil {
			return err
		}

		if status == "completed" {
			return nil
		} else {
			time.Sleep(time.Second * 30)
		}

	}
}

// Returns the nessus XML report for the specified scan as a string
func (n *Nessus) ExportAsNessus(scanId int) (string, error) {
	values := map[string]string{
		"format": "nessus",
	}
	jsonValues, _ := json.Marshal(values)

	req, err := http.NewRequest("POST", n.Url+fmt.Sprintf("/scans/%d/export"), bytes.NewBuffer(jsonValues))

	if err != nil {
		log.Fatal(err)
	}

	req.Header.Set("X-Cookie", "token="+n.Token)
	req.Header.Set("X-API-Token", n.ApiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.HttpClient.Do(req)

	if err != nil {
		return "", err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	token, err := jsonparser.GetString(body, "token")

	for {
		time.Sleep(time.Second * 5)

		req, err := http.NewRequest("GET", n.Url+fmt.Sprintf("/tokens/%s/download", token), nil)

		if err != nil {
			return "", err
		}

		req.Header.Set("X-Cookie", "token="+n.Token)
		req.Header.Set("X-API-Token", n.ApiKey)
		req.Header.Set("Content-Type", "application/json")

		resp, err := n.HttpClient.Do(req)

		if resp.StatusCode == http.StatusNotFound {
			continue
		}

		report, _ := ioutil.ReadAll(resp.Body)
		return string(report), nil

	}
}

// Launches a nessus scan using the standard template, see templates.go for more details
func (n *Nessus) LaunchScan(name string, targets string) int {
	config := config{
		Name:    name,
		Targets: targets,
	}

	t, err := template.New("scan").Parse(BasicTemplate)
	if err != nil {
		log.Fatal(err)
	}

	var tpl bytes.Buffer

	if err := t.Execute(&tpl, config); err != nil {
		log.Fatal(err)
	}

	req, err := http.NewRequest("POST", n.Url+"/scans", bytes.NewReader(tpl.Bytes()))

	if err != nil {
		log.Fatal(err)
	}

	req.Header.Set("X-Cookie", "token="+n.Token)
	req.Header.Set("X-API-Token", n.ApiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.HttpClient.Do(req)

	if err != nil {
		log.Fatal(err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	id, err := jsonparser.GetInt(body, "id")
	if err != nil {
		log.Fatal(err)
	}

	return int(id)
}