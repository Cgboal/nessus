package main

import (
	"flag"
	"fmt"
	"github.com/Cgboal/nessus"
	"log"
	"os"
)

func main() {
	hostname, _ := os.Hostname()

	targets := flag.String("t", "", "Comma seperated list of targets to feed to nessus")
	name := flag.String("n", "", "Name of the scan which shall be created")
	username := flag.String("u", "", "Nessus Username")
	password := flag.String("p", "", "Nessus password")
	nessus_location := flag.String("host", hostname, "Nessus hostname, defaults to os hostname")
	flag.Parse()

	url := fmt.Sprintf("https://%s", *nessus_location)
	nessus := nessus.NewNessus(url)

	if *targets == "" || *name == "" {
		flag.Usage()
		log.Fatal("Targets or name not specified")
	}

	if *password == "" || *username == "" {
		log.Println("Attempting to use NESSUS_USERNAME and NESSUS_PASSWORD environment variables")
		nessus.EnvCredentials()
	} else {
		nessus.Credentials(*username, *password)
	}

	nessus.Authenticate()
	_, err := nessus.LaunchScan(*name, *targets)
	if err != nil {
		log.Fatal(err)
	}
}
