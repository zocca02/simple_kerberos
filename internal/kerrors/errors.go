package kerrors

type ReplyError struct {
	Msg string
}

func (e *ReplyError) Error() string {
	return e.Msg
}

type PasswordError struct {
	Msg string
}

func (e *PasswordError) Error() string {
	return e.Msg
}

type TokenError struct {
	Msg string
}

func (e *TokenError) Error() string {
	return e.Msg
}
