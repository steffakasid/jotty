package internal

import (
	"bufio"
	"io"
	"io/ioutil"
	"os"
)

func ReadData(file string) (data []byte, err error) {
	if file == "-" {
		return ReadPipedData()
	} else {
		return ioutil.ReadFile(file)
	}
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
