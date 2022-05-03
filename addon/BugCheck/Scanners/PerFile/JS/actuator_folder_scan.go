package PerFolder

import (
	"jray/addon/BugCheck/Common"
	"regexp"
	"strings"
)

type RegexpStruct struct {
	name  string
	regxs *regexp.Regexp
}

var regxs = []RegexpStruct{}

func init() {
	Common.AddBugScanListPerFileJs(JsSensitiveContentScan{Common.PluginBase{Name: "js文件敏感内容匹配", Desc: "从返回js的包中匹配敏感内容", Type: "信息泄露", Ltype: "JS"}})

	regx := map[string]string{
		//# "邮箱信息": r'[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)+',
		"Token或密码": "\b(?:secret|secret_key|token|secret_token|auth_token|access_token|username|password|aws_access_key_id|aws_secret_access_key|secretkey|authtoken|accesstoken|access-token|authkey|client_secret|bucket|email|HEROKU_API_KEY|SF_USERNAME|PT_TOKEN|id_dsa|clientsecret|client-secret|encryption-key|pass|encryption_key|encryptionkey|secretkey|secret-key|bearer|JEKYLL_GITHUB_TOKEN|HOMEBREW_GITHUB_API_TOKEN|api_key|api_secret_key|api-key|private_key|client_key|client_id|sshkey|ssh_key|ssh-key|privatekey|DB_USERNAME|oauth_token|irc_pass|dbpasswd|xoxa-2|xoxrprivate-key|private_key|consumer_key|consumer_secret|access_token_secret|SLACK_BOT_TOKEN|slack_api_token|api_token|ConsumerKey|ConsumerSecret|SESSION_TOKEN|session_key|session_secret|slack_token|slack_secret_token|bot_access_token|passwd|api|eid|sid|api_key|apikey|userid|user_id|user-id)[\"\\s]*(?::|=|=:|=>)[\"\\s]*[a-z0-9A-Z]{8,64}\"?",
		//"IP地址": "\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
		"Cloudfront云泄露":   "[\\w]+\\.cloudfront\\.net",
		"Appspot云泄露":      "[\\w\\-.]+\\.appspot\\.com",
		"亚马逊云泄露":          "[\\w\\-.]*s3[\\w\\-.]*\\.?amazonaws\\.com\\/?[\\w\\-.]*",
		"Digitalocean云泄露": "([\\w\\-.]*\\.?digitaloceanspaces\\.com\\/?[\\w\\-.]*)",
		"Google云泄露":       "(storage\\.cloud\\.google\\.com\\/[\\w\\-.]+)",
		"Google存储API泄露":   "([\\w\\-.]*\\.?storage.googleapis.com\\/?[\\w\\-.]*)",
		"手机号":             "(?:139|138|137|136|135|134|147|150|151|152|157|158|159|178|182|183|184|187|188|198|130|131|132|155|156|166|185|186|145|175|176|133|153|177|173|180|181|189|170|171)[0-9]{8}",
		//# "域名泄露": r"((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:biz|cc|club|cn|com|co|edu|fun|group|info|ink|kim|link|live|ltd|mobi|net|online|org|pro|pub|red|ren|shop|site|store|tech|top|tv|vip|wang|wiki|work|xin|xyz|me))",
		"Access Key":           "access_key.*?[\"\\'](.*?)[\"\\']",
		"Access Key ID 1":      "accesskeyid.*?[\"\\\"](.*?)[\"\\']",
		"Access Key ID 2":      "accesskeyid.*?[\"\\'](.*?)[\"\\']",
		"Bearer":               "bearer [a-zA-Z0-9_\\-\\.=:_\\+\\/]{5,100}",
		"Facebook Token":       "EAACEdEose0cBA[0-9A-Za-z]+",
		"Github Token":         "[a-zA-Z0-9_-]*:[a-zA-Z0-9_\\-]+@github\\.com*",
		"JWT鉴权":                "ey[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.?[A-Za-z0-9-_.+/=]*$",
		"Mailgun服务密钥":          "key-[0-9a-zA-Z]{32}",
		"Paypal/Braintree访问凭证": "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}",
		"RSA密钥":                "-----BEGIN EC PRIVATE KEY-----",
		"DSA密钥":                "-----BEGIN DSA PRIVATE KEY-----",
		"Stripe账号泄露 1":         "rk_live_[0-9a-zA-Z]{24}",
		"Stripe账号泄露 2":         "sk_live_[0-9a-zA-Z]{24}",
	}
	for k, v := range regx {
		patternCompiled, err := regexp.Compile(v)
		if err != nil {
			continue
		}
		regxs = append(regxs, RegexpStruct{k, patternCompiled})
	}

}

type JsSensitiveContentScan struct {
	Common.PluginBase
}

func (p JsSensitiveContentScan) Exec(p1 Common.PluginBaseFun, request Common.Request, response Common.Response) {
	p.Request = request
	p.Response = response
	p.Audit()
}
func (p JsSensitiveContentScan) Audit() {
	if len(regxs) > 0 {
		for _, regx := range regxs {
			result := regx.regxs.FindStringSubmatch(string(p.Response.Body))
			if len(result) > 0 {
				p.Success(p.Name, p.Request.URL.String(), p.Type, regx.name, strings.Join(result, "||"))
			}
		}
	}
}
