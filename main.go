package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/mattn/go-colorable"
	json "github.com/neilotoole/jsoncolor"
	logger "github.com/sirupsen/logrus"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/steffakasid/jotty/internal"
)

const version = "0.1-development"

type config struct {
	File      string
	Header    bool
	Payload   bool
	Signature bool
	Version   bool
	Help      bool
	Loglevel  string
}

var conf = &config{}

func init() {
	flag.StringP("file", "f", "", "--file=<filename> read token from file or - from stdin")
	flag.BoolP("header", "h", true, "--header=false don't print the header of the JWT")
	flag.BoolP("payload", "p", true, "--payload=false don't print the payload of the JWT")
	flag.BoolP("signature", "s", true, "--signature=false don't print the signature of the JWT")
	flag.BoolP("version", "v", false, "--version print version information")
	flag.BoolP("help", "?", false, "--help print usage information")

	flag.Usage = func() {
		w := os.Stderr

		fmt.Fprintf(w, "Usage of %s: \n", os.Args[0])
		fmt.Fprintln(w, `
This tool allows to decrypt JSON Web Tokens called JWT (pronounced as jot). 
It just decodes the token and prints the JSON contents.

Usage:
  jotty [flags]

Examples:
  pbpaste | jotty -f -
  jotty -f test/jwt.txt
  jotty <jwt token data>
  pbpaste | jotty -f - --header=false --signature=false

Flags:`)

		flag.PrintDefaults()
	}

	flag.Parse()
	err := viper.BindPFlags(flag.CommandLine)
	CheckError(err, logger.Fatalf)
	err = viper.UnmarshalExact(conf)
	CheckError(err, logger.Fatalf)

	logger.SetLevel(logger.DebugLevel)
}

func main() {
	if conf.Version {
		fmt.Printf("jotty version: %s\n", version)
	} else if conf.Help {
		flag.Usage()
	} else {
		var jwt string
		if len(conf.File) > 0 {
			jwtBt, err := internal.ReadData(conf.File)
			CheckError(err, logger.Fatalf)
			jwt = string(jwtBt)
		} else {
			parsedArgs := parseArgs()
			if len(parsedArgs) == 1 {
				jwt = parsedArgs[0]
			} else {
				logger.Fatal("Only one argument is supported! Got", len(parsedArgs), parsedArgs)
			}
		}

		decodedJwt := internal.JWT{}
		err := decodedJwt.Decode(jwt)
		CheckError(err, logger.Fatalf)

		if conf.Header {
			colorfulJsonEncode(decodedJwt.Header)
		}

		if conf.Payload {
			colorfulJsonEncode(decodedJwt.Payload)
		}

		if conf.Signature {
			fmt.Println(decodedJwt.Signature)
		}
	}
}

func CheckError(err error, loggerFunc func(format string, args ...interface{})) (wasError bool) {
	wasError = false

	if err != nil {
		loggerFunc("%s\n", err)
	}
	return wasError
}

func colorfulJsonEncode(data map[string]interface{}) {
	var enc *json.Encoder

	if json.IsColorTerminal(os.Stdout) {
		out := colorable.NewColorable(os.Stdout) // needed for Windows
		enc = json.NewEncoder(out)
		clrs := json.DefaultColors()
		enc.SetColors(clrs)
	} else {
		enc = json.NewEncoder(os.Stdout)
	}

	enc.SetIndent("", "  ")

	if err := enc.Encode(data); err != nil {
		CheckError(err, logger.Fatalf)
	}
}

func parseArgs() []string {
	parsedArgs := []string{}
	for i, arg := range os.Args {
		if i != 0 && !strings.HasSuffix(arg, "-") {
			parsedArgs = append(parsedArgs, arg)
		}
	}
	return parsedArgs
}
