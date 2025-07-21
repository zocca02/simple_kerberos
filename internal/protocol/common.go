package protocol

import (
	"fmt"
	"simple_kerberos/internal/messages"
)

func errorReply(msg string, print bool) messages.Reply {
	if print {
		fmt.Println(msg)
	}
	return messages.Reply{
		IsError:       true,
		Message:       msg,
		EncryptedData: []byte{},
		EncDataMac:    []byte{},
	}
}
