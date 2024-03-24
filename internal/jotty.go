package internal

import (
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JottyConfig struct {
	File                   string        `mapstructure:"file"`
	NoHeader               bool          `mapstructure:"no-header"`
	NoPayload              bool          `mapstructure:"no-payload"`
	NoSignature            bool          `mapstructure:"no-signature"`
	Version                bool          `mapstructure:"version"`
	Help                   bool          `mapstructure:"help"`
	Loglevel               string        `mapstructure:"loglevel"`
	WithAudience           string        `mapstructure:"with-audience"`
	WithExpirationRequired bool          `mapstructure:"with-expiration"`
	WithIssuedAt           bool          `mapstructure:"with-issued-at"`
	WithIssuer             string        `mapstructure:"with-issuer"`
	WithJsonNumber         bool          `mapstructure:"with-json-number"`
	WithLeeway             time.Duration `mapstructure:"with-leeway"`
	WithPaddingAllowed     bool          `mapstructure:"with-padding-allowed"`
	WithStrictDecoding     bool          `mapstructure:"with-strict-decoding"`
	WithSubject            string        `mapstructure:"with-subject"`
	WithValidMethods       []string      `mapstructure:"with-valid-methods"`
	SigningKey             string        `mapstructure:"key-file"`
}

func (conf JottyConfig) GetParserOptions() (opts []jwt.ParserOption) {
	opts = []jwt.ParserOption{}

	if conf.WithAudience != "" {
		opts = append(opts, jwt.WithAudience(conf.WithAudience))
	}
	if conf.WithExpirationRequired {
		opts = append(opts, jwt.WithExpirationRequired())
	}
	if conf.WithIssuedAt {
		opts = append(opts, jwt.WithIssuedAt())
	}
	if conf.WithIssuer != "" {
		opts = append(opts, jwt.WithIssuer(conf.WithIssuer))
	}
	if conf.WithJsonNumber {
		opts = append(opts, jwt.WithJSONNumber())
	}
	if conf.WithLeeway > 0 {
		opts = append(opts, jwt.WithLeeway(conf.WithLeeway))
	}
	if conf.WithPaddingAllowed {
		opts = append(opts, jwt.WithPaddingAllowed())
	}
	if conf.WithStrictDecoding {
		opts = append(opts, jwt.WithStrictDecoding())
	}
	if conf.WithSubject != "" {
		opts = append(opts, jwt.WithSubject(conf.WithSubject))
	}
	if len(conf.WithValidMethods) > 0 {
		opts = append(opts, jwt.WithValidMethods(conf.WithValidMethods))
	}

	return opts
}

func (conf JottyConfig) GetPublicKey() (key []byte, err error) {
	if conf.SigningKey != "" {
		return os.ReadFile(conf.SigningKey)
	}
	return []byte("no key given"), nil
}
