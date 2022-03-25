package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	logger "github.com/sirupsen/logrus"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	fileFlag    = "file"
	versionFlag = "version"
	helpFlag    = "help"
)

func init() {
	flag.StringP(fileFlag, "f", "-", "Read token from file or - from stdin")
	flag.BoolP(versionFlag, "v", false, "Print version information")
	flag.BoolP(helpFlag, "?", false, "Print usage information")

	flag.Usage = func() {
		w := os.Stderr

		fmt.Fprintf(w, "Usage of %s: \n", os.Args[0])
		fmt.Fprintln(w, `
....

Usage:
  jotty [flags]

Examples:
  pbpaste | jotty -f -

Flags:`)

		flag.PrintDefaults()
	}

	flag.Parse()
	err := viper.BindPFlags(flag.CommandLine)
	CheckError(err, logger.Fatalf)
	logger.SetLevel(logger.DebugLevel)
}

func main() {
	jwtBt, err := ReadData(viper.GetString(fileFlag))
	CheckError(err, logger.Fatalf)
	jwt := string(jwtBt)

	jwtParts := strings.Split(jwt, ".")

	if len(jwtParts) == 3 {
		fmt.Println("Header:")
		Decode(jwtParts[0])
		fmt.Println()
		fmt.Println("Body:")
		Decode(jwtParts[1])
		fmt.Println()
		fmt.Println("Hash:")
		fmt.Println(jwtParts[2])
	} else {
		panic("invalid token")
	}

}

func Decode(str string) {
	bt, err := base64.URLEncoding.DecodeString(str + "==")
	CheckError(err, logger.Errorf)

	jsData := make(map[string]interface{})
	err = json.Unmarshal(bt, &jsData)
	CheckError(err, logger.Fatalf)

	marshaledJs, err := json.MarshalIndent(jsData, "", "  ")
	CheckError(err, logger.Errorf)
	fmt.Printf(string(marshaledJs))
}

func ReadData(file string) (data []byte, err error) {
	if file == "" {
		data = nil
		err = errors.New("you must provide the file flag")
	}
	if file == "-" {
		data, err = ReadPipedData()
	} else {
		data, err = ioutil.ReadFile(file)
	}
	return
}

func ReadPipedData() ([]byte, error) {
	reader := bufio.NewReader(os.Stdin)
	buf := make([]byte, 0, 4*1024)
	result := []byte{}

	for {
		n, err := reader.Read(buf[:cap(buf)])
		result = append(result, buf...)
		buf = buf[:n]
		if n == 0 {
			if err == nil {
				continue
			}
			if err == io.EOF {
				break
			}
			return nil, err
		}

		if err != nil && err != io.EOF {
			return nil, err
		}
	}
	return result, nil
}

func CheckError(err error, loggerFunc func(format string, args ...interface{})) (wasError bool) {
	wasError = false

	if err != nil {
		loggerFunc("%s\n", err)
	}
	return wasError
}
