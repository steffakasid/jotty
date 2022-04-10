package internal

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

type JWT struct {
	Header    map[string]interface{}
	Payload   map[string]interface{}
	Signature string
}

func (j *JWT) Decode(jwt string) error {
	jwtParts := strings.Split(jwt, ".")

	if len(jwtParts) != 3 {
		return fmt.Errorf("%s is not a JWT", jwt)
	}
	j.Signature = jwtParts[2]
	err := j.decodePart(jwtParts[0], &j.Header)
	if err != nil {
		return err
	}
	return j.decodePart(jwtParts[1], &j.Payload)
}

func (j *JWT) decodePart(part string, field *map[string]interface{}) error {

	if strings.Contains(part, ".") {
		return fmt.Errorf("%s doesn't look like a JWT part", part)
	}

	// base64 must be divisible by 4, otherwise padded with =
	part = fmt.Sprintf("%s%s", part, strings.Repeat("=", (len(part)%4)))

	bt, err := base64.URLEncoding.DecodeString(part)
	if err != nil {
		return err
	}

	err = json.Unmarshal(bt, field)
	if err != nil {
		return err
	}

	return nil
}
