package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mattn/go-colorable"
	json "github.com/neilotoole/jsoncolor"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/steffakasid/eslog"
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
	eslog.Logger.SetOutput(os.Stderr)

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
	eslog.LogIfError(err, eslog.Fatal)
	err = viper.UnmarshalExact(conf)
	eslog.LogIfError(err, eslog.Fatal)
}

func main() {
	if conf.Version {
		fmt.Printf("jotty version: %s\n", version)
	} else if conf.Help {
		flag.Usage()
	} else {
		var jwtRaw string
		if len(conf.File) > 0 {
			jwtBt, err := internal.ReadData(conf.File)
			eslog.LogIfError(err, eslog.Error)
			jwtRaw = string(jwtBt)
		} else {
			parsedArgs := parseArgs()
			if len(parsedArgs) == 1 {
				jwtRaw = parsedArgs[0]
			} else {
				eslog.Fatal("Only one argument is supported! Got", len(parsedArgs), parsedArgs)
			}
		}

		decodedJWT, err := jwt.Parse(jwtRaw, func(token *jwt.Token) (interface{}, error) {
			return []byte("AllYourBase"), nil
		})
		switch {
		case decodedJWT == nil:
			eslog.Fatal("Couldn't handle this token:", err)
		case decodedJWT.Valid:
			fmt.Println("JWT token is valid")
		default:
			eslog.Error("Error parsing the JWT:", err)
		}

		if conf.Header {
			colorfulJsonEncode(decodedJWT.Header)
		}

		if conf.Payload {
			colorfulJsonEncode(decodedJWT.Claims)
		}

		if conf.Signature {
			fmt.Println("JWT Signature:")
			fmt.Println(decodedJWT.Signature)
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

func colorfulJsonEncode(data any) {
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
		eslog.Error(err)
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
