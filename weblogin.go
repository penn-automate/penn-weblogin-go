package weblogin

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
	cookiejar "github.com/juju/persistent-cookiejar"
)

func NewWebLogin(cfg Config) (*WebLogin, error) {
	jar, err := cookiejar.New(&cookiejar.Options{
		Filename:  cfg.CookieFile,
		NoPersist: cfg.CookieFile == "",
	})
	if err != nil {
		return nil, err
	}
	return &WebLogin{
		config: cfg,
		jar:    jar,
		client: &http.Client{Jar: jar},
	}, nil
}

func (w *WebLogin) Do(req *http.Request) (*http.Response, error) {
	defer w.jar.Save()
	return w.do(req, false)
}

func (w *WebLogin) do(req *http.Request, lastLogin bool) (*http.Response, error) {
	resp, err := w.client.Do(req)
	if err != nil {
		return nil, err
	}

	u := resp.Request.URL
	if u.Host != "weblogin.pennkey.upenn.edu" || u.Path != "/idp/profile/SAML2/Redirect/SSO" {
		return resp, nil
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, err
	}

	form := doc.Find("form")

	val, exists := form.Attr("id")
	if !exists {
		return w.final(u, form)
	}

	switch val {
	case loginFormId:
		if lastLogin {
			return nil, errors.New("unknown error occurred")
		}
		formErr := doc.Find("p.form-error")
		if formErr.Length() != 0 {
			return nil, errors.New(formErr.Text())
		}
		return w.login(u, form)
	case twoStepFormId:
		return w.twoStep(u, form)
	}
	return nil, errors.New("unknown form action " + val)
}

func (w *WebLogin) login(u *url.URL, form *goquery.Selection) (*http.Response, error) {
	if w.config.CredentialFunc == nil {
		return nil, errors.New("login requires credential function")
	}

	val, exists := form.Attr("action")
	if !exists {
		return nil, formError
	}
	parsed, err := u.Parse(val)
	if err != nil {
		return nil, err
	}

	userAttr, exists := form.Find("input#pennname").Attr("name")
	if !exists {
		return nil, formError
	}

	passAttr, exists := form.Find("input#password").Attr("name")
	if !exists {
		return nil, formError
	}

	btnAttr, exists := form.Find("button").Attr("name")
	if !exists {
		return nil, formError
	}

	username, password := w.config.CredentialFunc()
	if username == "" || password == "" {
		return nil, errors.New("user cancelled login")
	}

	header := make(http.Header)
	header.Add("Content-Type", "application/x-www-form-urlencoded")

	params := make(url.Values)
	params.Add(userAttr, username)
	params.Add(passAttr, password)
	params.Add(btnAttr, "")

	return w.do(&http.Request{
		Method: http.MethodPost,
		URL:    parsed,
		Header: header,
		Body:   io.NopCloser(strings.NewReader(params.Encode())),
	}, true)
}

func (w *WebLogin) twoStep(u *url.URL, form *goquery.Selection) (*http.Response, error) {
	if w.config.CredentialFunc == nil {
		return nil, errors.New("login requires two factor function")
	}

	val, exists := form.Attr("action")
	if !exists {
		return nil, formError
	}
	parsed, err := u.Parse(val)
	if err != nil {
		return nil, err
	}

	// TODO: support other options
	tokenAttr, exists := form.Find("input#penntoken").Attr("name")
	if !exists {
		return nil, formError
	}

	header := make(http.Header)
	header.Add("Content-Type", "application/x-www-form-urlencoded")

	params := make(url.Values)

	token, trust := w.config.TwoFactorFunc()
	if token == "" {
		return nil, errors.New("user cancelled login")
	}
	if trust {
		trustAttr, exists := form.Find("input#trust-device-checkbox").Attr("name")
		if !exists {
			return nil, formError
		}
		params.Add(trustAttr, "true")
	}
	params.Add(tokenAttr, token)

	return w.do(&http.Request{
		Method: http.MethodPost,
		URL:    parsed,
		Header: header,
		Body:   io.NopCloser(strings.NewReader(params.Encode())),
	}, true)
}

func (w *WebLogin) final(u *url.URL, form *goquery.Selection) (*http.Response, error) {
	val, e := form.Attr("action")
	if !e {
		return nil, errors.New("cannot retrieve form id or action")
	}
	parsed, err := u.Parse(val)
	if err != nil {
		return nil, err
	}

	params := make(url.Values)
	inputs := form.Find(`input[type="hidden"]`)
	for i := 0; i < inputs.Length(); i++ {
		ele := inputs.Eq(i)
		if name, ok := ele.Attr("name"); !ok {
			return nil, formError
		} else if value, ok := ele.Attr("value"); !ok {
			return nil, formError
		} else {
			params.Set(name, value)
		}
	}

	header := make(http.Header)
	header.Add("Content-Type", "application/x-www-form-urlencoded")

	return w.do(&http.Request{
		Method: http.MethodPost,
		URL:    parsed,
		Header: header,
		Body:   io.NopCloser(strings.NewReader(params.Encode())),
	}, true)
}

const (
	loginFormId   = "login-form"
	twoStepFormId = "two-step-form"
)

var formError = errors.New("cannot retrieve form action")
