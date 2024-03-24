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

var conf = &internal.JottyConfig{}

const (
	fileFlag        = "file"
	noHeaderFlag    = "no-header"
	noPayloadFlag   = "no-payload"
	noSignatureFlag = "no-signature"
	versionFlag     = "version"
	helpFlag        = "help"

	withAudienceFlag           = "with-audience"
	withExpirationRequiredFlag = "with-expiration"
	withIssuedAtFlag           = "with-issued-at"
	withIssuerFlag             = "with-issuer"
	withJSONNumberFlag         = "with-json-number"
	withLeewayFlag             = "with-leeway"
	withPaddingAllowedFlag     = "with-padding-allowed"
	withStrictDecodingFlag     = "with-strict-decoding"
	withSubjectFlag            = "with-subject"
	withValidMethodFlag        = "with-valid-methods"

	keyFileFlag = "key-file"
)

func init() {
	eslog.Logger.SetOutput(os.Stderr)

	flag.StringP(fileFlag, "f", "", "Read token from  given file or if '-' from stdin.")
	flag.BoolP(noHeaderFlag, "h", false, "Don't print the header of the JWT.")
	flag.BoolP(noPayloadFlag, "p", false, "Don't print the payload of the JWT.")
	flag.BoolP(noSignatureFlag, "s", false, "Don't print the signature of the JWT.")
	flag.BoolP(versionFlag, "v", false, "Print version information.")
	flag.BoolP(helpFlag, "?", false, "Print usage information.")

	flag.String(withAudienceFlag, "", "Configures the validator to require the specified audience in the `aud` claim.")
	flag.Bool(withExpirationRequiredFlag, false, "This makes the exp claim required. By default exp claim is optional.")
	flag.Bool(withIssuedAtFlag, false, "Enables verification of issued-at.")
	flag.String(withIssuerFlag, "", "Require the specified issuer in the `iss` claim. Validation will fail if a different issuer is specified")
	flag.Bool(withJSONNumberFlag, false, "Configures the underlying JSON parser with UseNumber.")
	flag.Duration(withLeewayFlag, 0, "Specify the leeway window as duration e.g. 5s.")
	flag.Bool(withPaddingAllowedFlag, false, "Enable the codec used for decoding JWTs to allow padding. Note that the JWS RFC7515 states that the tokens will utilize a Base64url encoding with no padding.")
	flag.Bool(withStrictDecodingFlag, false, "Switch the codec used for decoding JWTs into strict mode. In this mode, the decoder requires that trailing padding bits are zero, as described in RFC 4648 section 3.5.")
	flag.String(withSubjectFlag, "", "Configures the validator to require the specified subject in the `sub` claim.")
	flag.StringArray(withValidMethodFlag, []string{}, "Supply algorithm methods that the parser will check.")

	flag.StringP(keyFileFlag, "k", "", "Provide the path to a PEM file containing the Key used to sign the JWT.")

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
  pbpaste | jotty -f - --no-header=false --no-signature

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

		opts := conf.GetParserOptions()
		signingKey, err := conf.GetPublicKey()
		eslog.LogIfError(err, eslog.Fatal)

		decodedJWT, err := jwt.Parse(jwtRaw, func(token *jwt.Token) (interface{}, error) {
			// TODO: verify token alge here https://pkg.go.dev/github.com/golang-jwt/jwt/v5#example-Parse-Hmac
			return signingKey, nil
		}, opts...)
		switch {
		case decodedJWT == nil:
			eslog.Fatal("Couldn't handle this token:", err)
		case decodedJWT.Valid:
			fmt.Println("JWT token is valid")
		default:
			eslog.Error("Error parsing the JWT:", err)
		}

		if !conf.NoHeader {
			colorfulJsonEncode(decodedJWT.Header)
		}

		if !conf.NoPayload {
			colorfulJsonEncode(decodedJWT.Claims)
		}

		if !conf.NoSignature {
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
