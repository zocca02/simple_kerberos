package messages

type Ticket struct {
	Key           []byte
	ClientId      string
	ClientAddress string
	TGSId         string
	Timestamp     int64
	Lifetime      int64
}

type ASRequest struct {
	ClientId  string
	TGSId     string
	Timestamp int64
}

type ASReply struct {
	KeyClientTGS  []byte
	TGSId         string
	Timestamp     int64
	Lifetime      int64
	CryptedTicket []byte
}
