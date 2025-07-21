package messages

/*

C -> ASRequest -> AS
AS -> E(TicketData) -> Reply -> C

C -> TGSRequest -> TGS
TGS -> E(TicketData) -> Reply -> C

C -> ServiceRequest -> V
V -> E(TS+1) -> Reply -> C

*/

type Reply struct {
	IsError       bool
	Message       string
	EncryptedData []byte
	EncDataMac    []byte
}

type ASRequest struct {
	ClientId  string
	TGSId     string
	Timestamp int64
}

type TGSRequest struct {
	ServiceId              string
	EncryptedTicket        []byte
	EncTicketMac           []byte
	EncryptedAuthenticator []byte
	EncAuthenticatorMac    []byte
}

type ServiceRequest struct {
	EncryptedTicket        []byte
	EncTicketMac           []byte
	EncryptedAuthenticator []byte
	EncAuthenticatorMac    []byte
}

type ServiceReply struct {
	Timestamp int64
}
