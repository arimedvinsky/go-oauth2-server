package main

import (
	"log"
	"os"

	"github.com/RichardKnop/go-oauth2-server/cmd"
	"github.com/urfave/cli"
)

var (
	cliApp        *cli.App
	configBackend string
)

func init() {
	// Initialise a CLI app
	cliApp = cli.NewApp()
	cliApp.Name = "go-oauth2-server"
	cliApp.Usage = "Go OAuth 2.0 Server"
	cliApp.Author = "Richard Knop"
	cliApp.Email = "risoknop@gmail.com"
	cliApp.Version = "0.0.0"
	cliApp.Flags = []cli.Flag{
		cli.StringFlag{
			Name:        "configBackend",
			Value:       "etcd",
			Destination: &configBackend,
		},
	}
}

func main() {
	// Set the CLI app commands
	cliApp.Commands = []cli.Command{
		{
			Name:  "migrate",
			Usage: "run migrations",
			Action: func(c *cli.Context) error {
				return cmd.Migrate(configBackend)
			},
		},
		{
			Name:  "loaddata",
			Usage: "load data from fixture",
			Action: func(c *cli.Context) error {
				return cmd.LoadData(c.Args(), configBackend)
			},
		},
		{
			Name:  "runserver",
			Usage: "run web server",
			Action: func(c *cli.Context) error {
				return cmd.RunServer(configBackend)
			},
		},
	}

	// Run the CLI app
	if err := cliApp.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func main1() {

	/*//jwt "github.com/dgrijalva/jwt-go"
	fbAcessToken := "EAALZCjLAksHwBAI3R8CoVbA7gkWjUwdQUO3RMtVMHvgznAcrCJVwJ7szkEnrxhYTrqRAgxPfG8hPXS97f49Av7iXyH59ZBi4Q32CslUIbB8TL9o3yoCrhUxsR1PnIu4UzToUnnRsZCOIoSOyXD4jOZC7WXPN5nZCCb8gMUx2iRwZDZD"
	serviceID := "PASSENGER"

	lr, err := web.LoginWithGrabViaFacebook(fbAcessToken, serviceID)
	if err != nil {
		fmt.Printf("Error calling LoginWithGrabViaFacebook, error %v", err)
		return
	}

	grabIDJWT := &jwt.Token{}
	fn := func(token *jwt.Token) (interface{}, error) {
		grabIDJWT = token
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("ErrorTokenInvalidSig")
		}
		return nil, nil
	}


	tk := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJQQVNTRU5HRVIiLCJleHAiOjE1MjExNTQyODUsImlhdCI6MTUyMTA2Nzg4NSwianRpIjoiYzBmNjM2MDMtZGExNS00MmVmLWExYTgtNjNhNTViNTVkNDFkIiwibG1lIjoiRkFDRUJPT0siLCJuYW1lIjoiIiwic3ViIjoiNWFlOWI2OTMtY2ZkMC00ZjUwLWJiZjUtNjg5MGNmOThmNzhiIn0.ccry_54IzE3OaNPUo0Nk2x9QPkfGOefAZi65wyIEzC-QlAi862GCGWl5zoyFjobToKa-JuqF_ghF5V5ES16LKsGjznC6MQOr8-TrPtXvuqFDHu1tt3PDxWp93zzAUJhWjdg12CU2ZuuH54v1_YRqIeQLH-Q8vGSeA3yTCWBMpwzM3hJku-apZYwzRz_WEU9a8SFKz_cP0_PKFSUEOmuVbW1NaXjB8CxqafFIebMLzQo5QNcZvyzsxKo6PEVCbgteZOb94mely-C87OOML1kahuWT0f8GY5gt4I70yPtn8vFNbgoEFBDiZ0FAQJTSYTDVNTxuimKeObrV0j2xCJhaaRLqCLqsNv_FXFphYne349Tc4Nbl0gXaBnxDpQtt4V4tPhIVNv1Al83qV-8YFns1JJNgsUQgYWIY9fQ7AhX8q7pP9UWq6qNzLucu6GflanVPEtHhIfMqSrGnKYs5ySQKH2AXtkONCO01tEnE4wLX5AzTX22tdfxsT1-yGQdYcwfZJmdvMOqXtNSEXRhyGlUlBfDwgwCb-CGL4x_JWLY1SSe_-T_RXxM7Wz3TCzK-4S4JTyYA50ZsIJgE6MDS1Ff4QP2GdoEOoj1z54PEcsPsJ--SOCzUtkD1wpj5KHaelaX_XYcxRGLm9rA0_4PSzkxfn83P8-9bdchoDA-udG0G49Y"

	fmt.Printf("Login result:\n +%v\n", lr)
	grabIDJWT, _ := jwt.Parse(tk, nil)
	claims, _ := grabIDJWT.Claims.(jwt.MapClaims)

	fmt.Printf("%v\n", claims["jti"]) */
}
