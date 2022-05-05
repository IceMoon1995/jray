package Common

type Reverse struct {
	ReverseDomain      string
	ReverseCheckDomain string
	//ReversePort        int
	ReverseType        string
	ReverseAccessKeyId string
	Other              string
}

var LdapReverse = Reverse{ReverseDomain: "127.0.0.1:1389", ReverseCheckDomain: "http://127.0.0.1:8080/%s.md5", ReverseType: "ldap"}

var ReverseMap = map[string]Reverse{}

func init() {
	ReverseMap["ldap"] = LdapReverse
}
