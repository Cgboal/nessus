#### Introduction
This repository provides a golang library which can be used to launch and export nessus scans by interacting with the web api directly. 

#### Usage

See the relevant godocs for more in-depth usage information.

If you don't want to use the library, and only launch scans, you can install the minimal scan launcher script with `go get github.com/Cgboal/nessus/nessuscli`.

#### Example usage
The following code snippet shows how this library can be used to launch nessus scans. 

``` golang
package main

import (
	"github.com/cgboal/nessus"
	"os"
	"fmt"
	"flag"
	"log"
)

func main () {
	hostname, _ := os.Hostname()

	targets := flag.String("t", "", "Comma seperated list of targets to feed to nessus")
	name := flag.String("n", "", "Name of the scan which shall be created")
	username := flag.String("u", "", "Nessus Username")
	password := flag.String("p", "", "Nessus password")
	nessus_location := flag.String("host", hostname, "Nessus hostname, defaults to os hostname")
	flag.Parse()

	url := fmt.Sprintf("https://%s:8834", *nessus_location)
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
	scanId := nessus.LaunchScan(*name, *targets)
    
    nessus.Wait(scanId)
    report, _ := nessus.ExportAsNessus(scanId)
    fmt.Println(report)

}

```
