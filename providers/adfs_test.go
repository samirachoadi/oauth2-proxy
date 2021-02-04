package providers

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

func testAdfsProvider(hostname string) *AdfsProvider {
	p := NewAdfsProvider(
		&ProviderData{
			ProviderName: "",
			LoginURL:     &url.URL{},
			RedeemURL:    &url.URL{},
			ProfileURL:   &url.URL{},
			ValidateURL:  &url.URL{},
			Scope:        ""})

	if hostname != "" {
		updateURL(p.Data().LoginURL, hostname)
		updateURL(p.Data().RedeemURL, hostname)
		updateURL(p.Data().ProfileURL, hostname)
		updateURL(p.Data().ValidateURL, hostname)
	}

	return p
}

func testAdfsBackend() *httptest.Server {

	authResponse := `
		{
			"access_token": "my_access_token",
			"id_token": "my_id_token",
			"refresh_token": "my_refresh_token" 
		 }
	`
	userInfo := `
		{
			"email": "samiracho@email.com"
		}
	`

	refreshResponse := `{ "access_token": "new_some_access_token", "refresh_token": "new_some_refresh_token", "expires_in": "32693148245", "id_token": "new_some_id_token" }`

	authHeader := "Bearer adfs_access_token"

	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/adfs/oauth2/authorize":
				w.WriteHeader(200)
				w.Write([]byte(authResponse))
			case "/adfs/oauth2/refresh":
				w.WriteHeader(200)
				w.Write([]byte(refreshResponse))
			case "/adfs/oauth2/userinfo":
				if r.Header["Authorization"][0] == authHeader {
					w.WriteHeader(200)
					w.Write([]byte(userInfo))
				} else {
					w.WriteHeader(401)
				}
			default:
				w.WriteHeader(200)
			}
		}))
}

var _ = Describe("Adfs Provider Tests", func() {
	var p *AdfsProvider
	var b *httptest.Server

	BeforeEach(func() {
		b = testAdfsBackend()

		bURL, err := url.Parse(b.URL)
		Expect(err).To(BeNil())

		p = testAdfsProvider(bURL.Host)
	})

	AfterEach(func() {
		b.Close()
	})

	Context("New Provider Init", func() {
		It("uses defaults", func() {
			providerData := NewAdfsProvider(&ProviderData{}).Data()
			Expect(providerData.ProviderName).To(Equal("Adfs"))
			Expect(providerData.Scope).To(Equal("openid"))
		})

		It("overrides defaults", func() {
			p := NewAdfsProvider(
				&ProviderData{
					LoginURL: &url.URL{
						Scheme: "https",
						Host:   "example.com",
						Path:   "/adfs/oauth2/authorize"},
					RedeemURL: &url.URL{
						Scheme: "https",
						Host:   "example.com",
						Path:   "/adfs/oauth2/token"},
					ProfileURL: &url.URL{
						Scheme: "https",
						Host:   "example.com",
						Path:   "/adfs/oauth2/userinfo"},
					ValidateURL: &url.URL{
						Scheme: "https",
						Host:   "example.com",
						Path:   "/oauth2/userinfo"},
					Scope: "openid profile"})
			providerData := p.Data()

			Expect(providerData.ProviderName).To(Equal("Adfs"))
			Expect(providerData.LoginURL.String()).To(Equal("https://example.com/adfs/oauth2/authorize"))
			Expect(providerData.RedeemURL.String()).To(Equal("https://example.com/adfs/oauth2/token"))
			Expect(providerData.ProfileURL.String()).To(Equal("https://example.com/adfs/oauth2/userinfo"))
			Expect(providerData.ValidateURL.String()).To(Equal("https://example.com/oauth2/userinfo"))
			Expect(providerData.Scope).To(Equal("openid profile"))
		})
	})

	Context("with bad token", func() {
		It("should trigger an error", func() {
			session := &sessions.SessionState{AccessToken: "unexpected_gitlab_access_token", IDToken: "malformed_token"}
			err := p.EnrichSession(context.Background(), session)
			Expect(err).To(MatchError(errors.New("failed to parse token, wrong format")))
		})
	})

	Context("with valid token", func() {
		It("should get the email", func() {
			token := "header." + base64.URLEncoding.EncodeToString([]byte(`{"upn": "samirachoadi@email.com"}`)) + ".signature"
			session := &sessions.SessionState{IDToken: token}
			err := p.EnrichSession(context.Background(), session)
			Expect(err).To(BeNil())
			Expect(session.Email).To(Equal("samirachoadi@email.com"))
		})
	})

	Context("with resource parameter", func() {
		It("should return correct loginUrl", func() {
			p.ProtectedResource, _ = url.Parse("http://my.resource.test")
			result := p.GetLoginURL("https://example.com/adfs/oauth2/", "")
			Expect(result).To(ContainSubstring("resource=" + url.QueryEscape("http://my.resource.test")))
		})
	})

	Context("when obtaining email", func() {
		type emailsTableInput struct {
			expectedError error
			expectedUser  string
			expectedEmail string
			token         string
		}

		DescribeTable("should return expected results",
			func(in emailsTableInput) {
				jwt := "header." + base64.URLEncoding.EncodeToString([]byte(in.token)) + ".signature"
				session := &sessions.SessionState{IDToken: jwt}

				err := p.EnrichSession(context.Background(), session)

				if in.expectedError != nil {
					Expect(err).To(MatchError(err))
				} else {
					Expect(err).To(BeNil())
					Expect(session.Email).To(Equal(in.expectedEmail))
					//Expect(session.User).To(Equal(in.expectedUser))
				}
			},
			Entry("should get email", emailsTableInput{
				expectedEmail: "samiracho@email.com",
				token:         `{"email": "samiracho@email.com"}`,
			}),
			Entry("should fallback to upn if email claim is missing", emailsTableInput{
				expectedEmail: "samirachoadiupn@email.com",
				expectedUser:  "samirachoadiupn@email.com",
				token:         `{"upn": "samirachoadiupn@email.com"}`,
			}),
			Entry("should get email if both upn and email are available", emailsTableInput{
				expectedUser:  "samirachoupn@email.com",
				expectedEmail: "samiracho@email.com",
				token:         `{"upn": "samirachoadiupn@email.com", "email": "samiracho@email.com"}`,
			}),
		)
	})

	Context("when handling tokens", func() {
		It("Gets tokens", func() {
			p.ProviderData.RedeemURL.Path = "/adfs/oauth2/authorize"
			session, err := p.Redeem(context.Background(), "https://localhost", "1234")
			Expect(err).To(BeNil())
			Expect(session.AccessToken).To(Equal("my_access_token"))
			Expect(session.IDToken).To(Equal("my_id_token"))
			Expect(session.RefreshToken).To(Equal("my_refresh_token"))
		})

		It("Should not refresh non expired token", func() {
			expires := time.Now().Add(time.Duration(1) * time.Hour)
			session := &sessions.SessionState{AccessToken: "some_access_token", RefreshToken: "some_refresh_token", IDToken: "some_id_token", ExpiresOn: &expires}
			refreshNeeded, err := p.RefreshSessionIfNeeded(context.Background(), session)
			Expect(err).To(BeNil())
			Expect(refreshNeeded).To(BeFalse())
		})

		It("Should refresh expired token", func() {
			timestamp, _ := time.Parse(time.RFC3339, "3006-01-02T22:04:05Z")
			expires := time.Now().Add(time.Duration(-1) * time.Hour)
			p.ProviderData.RedeemURL.Path = "/adfs/oauth2/refresh"
			session := &sessions.SessionState{AccessToken: "some_access_token", RefreshToken: "some_refresh_token", IDToken: "some_id_token", ExpiresOn: &expires}
			_, err := p.RefreshSessionIfNeeded(context.Background(), session)
			Expect(err).To(BeNil())
			Expect(session.AccessToken).To(Equal("new_some_access_token"))
			Expect(session.RefreshToken).To(Equal("new_some_refresh_token"))
			Expect(session.IDToken).To(Equal("new_some_id_token"))
			Expect(timestamp).To(Equal(session.ExpiresOn.UTC()))
		})
	})
})
