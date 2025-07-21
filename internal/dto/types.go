package dto

type Client struct {
	DbId     int
	ClientId string
	Key      []byte
}

type TGS struct {
	DbId  int
	TgsId string
	Key   []byte
}

type Service struct {
	DbId      int
	ServiceId string
	Key       []byte
}

type TicketData struct {
	Key             []byte
	TargetId        string
	Timestamp       int64
	Lifetime        int64
	EncryptedTicket []byte
	EncTicketMac    []byte
}

type Ticket struct {
	Key           []byte
	ClientId      string
	ClientAddress string
	TargetId      string
	Timestamp     int64
	Lifetime      int64
}

type Authenticator struct {
	ClientId      string
	ClientAddress string
	Timestamp     int64
}
