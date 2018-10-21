package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/adedayo/sshscan"
	"gopkg.in/urfave/cli.v2"
)

var (
	version = "0.0.0" // deployed version will be taken from release tags
)

func main() {
	app := &cli.App{
		Name:    "sshscan",
		Version: version,
		Usage:   "Audit key exchange algorithms and settings on an SSH server",
		UsageText: `Audit key exchange settings on an SSH server. 
	
Example:
	
sshscan host

or, to specify a port explicitly :

sshscan -p 22222 host

`,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "port",
				Aliases: []string{"p"},
				Usage:   "specify an explicit port to scan",
				Value:   "22",
			},
			&cli.BoolFlag{
				Name:    "json",
				Aliases: []string{"j"},
				Usage:   "generate JSON output",
			},
		},

		Authors: []*cli.Author{
			&cli.Author{
				Name:  "Adedayo Adetoye (Dayo)",
				Email: "https://github.com/adedayo",
			},
		},

		Action: func(c *cli.Context) error {
			return process(c)
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}

}

func process(c *cli.Context) error {
	if c.NArg() == 0 {
		c.App.Run([]string{"sshscan", "h"})
		return nil
	}
	host := c.Args().First()
	port := c.String("port")

	if c.Bool("json") {
		js, _ := json.Marshal(sshscan.Inspect(host, port))
		println(string(js))
	} else {
		fmt.Printf("Starting SSHScan %s (%s)\n\n", version, "https://github.com/adedayo/sshscan")
		textOutput(sshscan.Inspect(host, port))
	}

	return nil
}

func textOutput(scan sshscan.SSHExchange) {
	if scan.Fail {
		fmt.Printf("SSH Scan of %s:%s failed with error: %s\n", scan.Server, scan.Port, scan.FailReason)
	} else {
		fmt.Printf("Server: %s\nPort: %s\nServer Version: %s\nRandom Cookie: %x\n", scan.Server, scan.Port, strings.TrimSpace(scan.ProtocolVersion), scan.Cookie)
		fmt.Printf("Key Exchange Algorithms: (%d)", len(scan.KEXAlgorithms))
		fmt.Printf("\n\t%s\n", strings.Join(scan.KEXAlgorithms, "\n\t"))
		fmt.Printf("Server Host Key Algorithms: (%d)", len(scan.ServerHostKeyAlgos))
		fmt.Printf("\n\t%s\n", strings.Join(scan.ServerHostKeyAlgos, "\n\t"))
		fmt.Printf("Server Encryption Algorithms: (%d)", len(scan.EncAlgosS2C))
		fmt.Printf("\n\t%s\n", strings.Join(scan.EncAlgosS2C, "\n\t"))
		fmt.Printf("Server MAC Algorithms: (%d)", len(scan.MACAlgosS2C))
		fmt.Printf("\n\t%s\n", strings.Join(scan.MACAlgosS2C, "\n\t"))
		fmt.Printf("Server Compression Algorithms: (%d)", len(scan.CompAlgosS2C))
		fmt.Printf("\n\t%s\n", strings.Join(scan.CompAlgosS2C, "\n\t"))
		fmt.Printf("Server Languages: (%d)", len(scan.LanguagesS2C))
		fmt.Printf("\n\t%s\n", strings.Join(scan.LanguagesS2C, "\n\t"))
	}

}
