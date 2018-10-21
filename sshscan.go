package sshscan

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

//SSHExchange contains parameters exchanged between server and client during the connection setup
//and key exchange algorithm negotiation step
//See https://tools.ietf.org/html/rfc4253
type SSHExchange struct {
	Server             string
	Port               string
	ProtocolVersion    string
	Cookie             [16]byte //random cookie
	KEXAlgorithms      []string //key exchange algorithms
	ServerHostKeyAlgos []string //server host ket algorithms
	EncAlgosC2S        []string //encryption algorithms client to server
	EncAlgosS2C        []string //encryption algorithms server to client
	MACAlgosC2S        []string //MAC algorithms client to server
	MACAlgosS2C        []string //MAC algorithms server to client
	CompAlgosC2S       []string //Compression algorithms client to server
	CompAlgosS2C       []string //Compression algorithms server to client
	LanguagesC2S       []string //Languages client to server
	LanguagesS2C       []string //Languages server to client
	Fail               bool     //if the inspection fails
	FailReason         string   //possible error information in the event of a failure

}

var (
	maxSize   = 35000 //Read max of 35k bytes. https://tools.ietf.org/html/rfc4253#section-6.1
	badServer = "Server %s is trying to overflow us ;-), we do not expect the key exchange to exceed 35000 bytes, but server is trying to access %d byte\n"
)

//Inspect returns an `SSHExchange` on the specified `host` and `port`. If the inspection fails
// `SSHExchange.Fail` is set to true, and a possible reason for failure is provided in `SSHExchange.FailReason`
func Inspect(host, port string) (data SSHExchange) {
	data.Server = host
	data.Port = port
	// see the SSH connection setup in https://tools.ietf.org/html/rfc4253 and https://www.ietf.org/rfc/rfc4251.txt
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 5*time.Second)
	if err != nil {
		data.Fail = true
		data.FailReason = err.Error()
		return
	}
	defer conn.Close()

	//get protocol version https://tools.ietf.org/html/rfc4253#section-4.2
	buf := make([]byte, 255)
	n, err := conn.Read(buf)
	if err != nil {
		data.Fail = true
		data.FailReason = err.Error()
		return
	}
	data.ProtocolVersion = string(buf[:n])
	_, err = conn.Write([]byte("SSH-2.0-sshscan\r\n"))
	if err != nil {
		data.Fail = true
		data.FailReason = err.Error()
		return
	}

	//Key Exchange, see https://tools.ietf.org/html/rfc4253#section-7.1
	buf = make([]byte, maxSize)
	_, err = conn.Read(buf)
	if err != nil {
		data.Fail = true
		data.FailReason = err.Error()
		return
	}
	var length uint32 // size of payload
	err = binary.Read(bytes.NewBuffer(buf[:4]), binary.BigEndian, &length)
	if err != nil {
		data.Fail = true
		data.FailReason = err.Error()
		return
	}
	if buf[5] != 20 { // ensure that we are looking at an SSH_MSG_KEXINIT
		data.Fail = true
		data.FailReason = fmt.Sprintf("Expecting an SSH_MSG_KEXINIT (0x%x), but got 0x%x", 20, buf[5])
		return
	}

	//Server Random Cookies
	payloadBegin := 5 /** uint32 (length) + byte (pad length) */ + 1 /** SSH_MSG_KEXINIT byte */ + 16 /** random 16 bytes cookie */
	copy(data.Cookie[:], buf[6:payloadBegin])

	//Key exchange algorithms
	var nextLength uint32
	begin := payloadBegin
	end := payloadBegin
	result, err := readNext(buf, &begin, &end, &nextLength, &data, host)
	if err != nil {
		return
	}
	data.KEXAlgorithms = result

	//Server host key algorithms
	result, err = readNext(buf, &begin, &end, &nextLength, &data, host)
	if err != nil {
		return
	}
	data.ServerHostKeyAlgos = result

	//encryption algorithms client-to-server
	result, err = readNext(buf, &begin, &end, &nextLength, &data, host)
	if err != nil {
		return
	}
	data.EncAlgosC2S = result

	//encryption algorithms server-to-client
	result, err = readNext(buf, &begin, &end, &nextLength, &data, host)
	if err != nil {
		return
	}
	data.EncAlgosS2C = result

	//MAC algorithms client-to-server
	result, err = readNext(buf, &begin, &end, &nextLength, &data, host)
	if err != nil {
		return
	}
	data.MACAlgosC2S = result

	//MAC algorithms server-to-client
	result, err = readNext(buf, &begin, &end, &nextLength, &data, host)
	if err != nil {
		return
	}
	data.MACAlgosS2C = result

	//compression algorithms client-to-server
	result, err = readNext(buf, &begin, &end, &nextLength, &data, host)
	if err != nil {
		return
	}
	data.CompAlgosC2S = result

	// compression algorithms server-to-client
	result, err = readNext(buf, &begin, &end, &nextLength, &data, host)
	if err != nil {
		return
	}
	data.CompAlgosS2C = result

	//languages client-to-server
	result, err = readNext(buf, &begin, &end, &nextLength, &data, host)
	if err != nil {
		return
	}
	data.LanguagesC2S = result

	// languages server-to-client
	result, err = readNext(buf, &begin, &end, &nextLength, &data, host)
	if err != nil {
		return
	}
	data.LanguagesS2C = result

	return
}

func readNext(buf []byte, begin, end *int, nextLength *uint32, data *SSHExchange, host string) (result []string, err error) {
	err = binary.Read(bytes.NewBuffer(buf[*end:*end+4]), binary.BigEndian, nextLength)
	if err != nil {
		data.Fail = true
		data.FailReason = err.Error()
		return
	}

	*begin = *end + 4
	*end = *begin + int(*nextLength)
	if *end > maxSize {
		data.Fail = true
		data.FailReason = fmt.Sprintf(badServer, host, *end)
		return
	}
	if *begin != *end {
		result = strings.Split(string(buf[*begin:*end]), ",")
	}
	return
}
