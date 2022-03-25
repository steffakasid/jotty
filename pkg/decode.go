package pkg

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
	err := j.decodeHeader(jwtParts[0])
	if err != nil {
		return err
	}
	return j.decodePayload(jwtParts[1])
}

func (j *JWT) decodeHeader(header string) error {
	if strings.Contains(header, ".") {
		return fmt.Errorf("%s doesn't look like a JWT header", header)
	}

	var err error
	j.Header, err = decodePart(header)
	return err
}

func (j *JWT) decodePayload(payload string) error {
	if strings.Contains(payload, ".") {
		return fmt.Errorf("%s doesn't look like a JWT payload", payload)
	}

	var err error
	j.Payload, err = decodePart(payload)
	return err
}

func decodePart(part string) (map[string]interface{}, error) {

	// base64 must be divisible by 4, otherwise padded with =
	part = fmt.Sprintf("%s%s", part, strings.Repeat("=", (len(part)%4)))

	bt, err := base64.URLEncoding.DecodeString(part)
	if err != nil {
		return nil, err
	}

	jsData := make(map[string]interface{})
	err = json.Unmarshal(bt, &jsData)
	if err != nil {
		return nil, err
	}

	return jsData, nil
}
