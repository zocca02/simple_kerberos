package config

const SymmKeyDim int = 128
const Lifetime int64 = 30 * 60 * 1000
const AuthenticatorFreshnessTime = 60 * 1000

const AsDbPath string = "./data/as.db"
const TgsDbPath string = "./data/"
const ClientDbPath string = "./data/client.db"
const ServiceKeyPath string = "./data/"

const AsPort int = 8888
const TgsPort int = 8889

var TgsList = []string{"tgs1", "tgs2"}
