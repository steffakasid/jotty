package main

import (
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mattn/go-colorable"
	"github.com/neilotoole/jsoncolor"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/steffakasid/eslog"
	flags "github.com/steffakasid/jotty/flags"
	jotty "github.com/steffakasid/jotty/internal"
)

const version = "0.1-development"

var conf = &jotty.Config{}

func init() {
	eslog.Logger.SetOutput(os.Stderr)

	// Define flags
	pflag.StringP(flags.File, "f", "", "Read token from given file or if '-' from stdin.")
	pflag.BoolP(flags.NoHeader, "h", false, "Don't print the header of the JWT.")
	pflag.BoolP(flags.NoPayload, "p", false, "Don't print the payload of the JWT.")
	pflag.BoolP(flags.NoSignature, "s", false, "Don't print the signature of the JWT.")
	pflag.BoolP(flags.Version, "v", false, "Print version information.")
	pflag.BoolP(flags.Help, "?", false, "Print usage information.")
	pflag.String(flags.WithAudience, "", "Configures the validator to require the specified audience in the `aud` claim.")
	pflag.Bool(flags.WithExpirationRequired, false, "This makes the exp claim required. By default exp claim is optional.")
	pflag.Bool(flags.WithIssuedAt, false, "Enables verification of issued-at.")
	pflag.String(flags.WithIssuer, "", "Require the specified issuer in the `iss` claim. Validation will fail if a different issuer is specified")
	pflag.Bool(flags.WithJSONNumber, false, "Configures the underlying JSON parser with UseNumber.")
	pflag.Duration(flags.WithLeeway, 0, "Specify the leeway window as duration e.g. 5s.")
	pflag.Bool(flags.WithPaddingAllowed, false, "Enable the codec used for decoding JWTs to allow padding. Note that the JWS RFC7515 states that the tokens will utilize a Base64url encoding with no padding.")
	pflag.Bool(flags.WithStrictDecoding, false, "Switch the codec used for decoding JWTs into strict mode. In this mode, the decoder requires that trailing padding bits are zero, as described in RFC 4648 section 3.5.")
	pflag.String(flags.WithSubject, "", "Configures the validator to require the specified subject in the `sub` claim.")
	pflag.StringArray(flags.WithValidMethod, []string{}, "Supply algorithm methods that the parser will check.")
	pflag.StringP(flags.KeyFile, "k", "", "Provide the path to a PEM file containing the Key used to sign the JWT. Otherwise signature can't be verified and will not be printed.")

	// Define usage
	pflag.Usage = func() {
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
  pbpaste | jotty -f - --no-header --no-signature`)
		pflag.PrintDefaults()
	}

	// Parse flags and bind to viper
	pflag.Parse()
	err := viper.BindPFlags(pflag.CommandLine)
	eslog.LogIfError(err, eslog.Fatal)
	err = viper.UnmarshalExact(conf)
	eslog.LogIfError(err, eslog.Fatal)
}

func main() {
	if conf.Version {
		fmt.Printf("jotty version: %s\n", version)
	} else if conf.Help {
		pflag.Usage()
	} else {
		var jwtRaw string
		var decodedJWT *jwt.Token
		var err error

		if len(conf.File) > 0 {
			jwtBt, err := jotty.ReadData(conf.File)
			eslog.LogIfError(err, eslog.Error)
			jwtRaw = string(jwtBt)
		} else {
			eslog.Fatal(fmt.Sprintf("No JWT token provided. At least --%s must be provided.", flags.File))
		}

		opts := conf.GetParserOptions()
		signingKey, err := conf.GetPublicKey()
		eslog.LogIfError(err, eslog.Fatal)

		parser := jwt.NewParser(opts...)

		if conf.SigningKey == "" {
			decodedJWT, _, err = parser.ParseUnverified(jwtRaw, jwt.MapClaims{})
		} else {
			decodedJWT, err = parser.Parse(jwtRaw, func(token *jwt.Token) (interface{}, error) {
				return signingKey, nil
			})
		}

		switch {
		case decodedJWT == nil:
			eslog.Fatal("Couldn't handle this token:", err)
		case decodedJWT.Valid:
			fmt.Println("JWT token is valid")
		case err != nil:
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
		wasError = true
	}
	return wasError
}

func colorfulJsonEncode(data any) {
	var enc *jsoncolor.Encoder
	if jsoncolor.IsColorTerminal(os.Stdout) {
		out := colorable.NewColorable(os.Stdout) // needed for Windows
		enc = jsoncolor.NewEncoder(out)
		clrs := jsoncolor.DefaultColors()
		enc.SetColors(clrs)
	} else {
		enc = jsoncolor.NewEncoder(os.Stdout)
	}
	enc.SetIndent("", "  ")
	if err := enc.Encode(data); err != nil {
		eslog.Error(err)
	}
}
