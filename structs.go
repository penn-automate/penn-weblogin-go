package weblogin

import (
	"net/http"

	cookiejar "github.com/juju/persistent-cookiejar"
)

type Config struct {
	CookieFile string

	CredentialFunc func() (username, password string)
	TwoFactorFunc  func() (token string, trust bool)
}

type WebLogin struct {
	config Config
	jar    *cookiejar.Jar
	client *http.Client
}
