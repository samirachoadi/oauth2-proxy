package providers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

// AdfsProvider represents an ADFS based Identity Provider
type AdfsProvider struct {
	*ProviderData
}

var _ Provider = (*AdfsProvider)(nil)

const (
	adfsProviderName = "Adfs"
	adfsDefaultScope = "openid"
)

type adfsClaims struct {
	Upn   string `json:"upn"`
	Email string `json:"email"`
}

// NewAdfsProvider initiates a new AdfsProvider
func NewAdfsProvider(p *ProviderData) *AdfsProvider {
	p.setProviderDefaults(providerDefaults{
		name:  adfsProviderName,
		scope: adfsDefaultScope,
	})

	return &AdfsProvider{ProviderData: p}
}

// GetLoginURL overrides GetLoginURL to add Adfs parameters
func (p *AdfsProvider) GetLoginURL(redirectURI, state string) string {
	extraParams := url.Values{}
	if p.ProtectedResource != nil && p.ProtectedResource.String() != "" {
		extraParams.Add("resource", p.ProtectedResource.String())
	}
	a := makeLoginURL(p.ProviderData, redirectURI, state, extraParams)
	return a.String()
}

// Redeem exchanges the OAuth2 authentication token for an Access\ID tokens
func (p *AdfsProvider) Redeem(ctx context.Context, redirectURL, code string) (s *sessions.SessionState, err error) {
	if code == "" {
		return nil, ErrMissingCode
	}
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return nil, err
	}

	var jsonResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		IDToken      string `json:"id_token"`
	}

	params := url.Values{}
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", clientSecret)
	if p.ProtectedResource != nil && p.ProtectedResource.String() != "" {
		params.Add("resource", p.ProtectedResource.String())
	}
	params.Add("grant_type", "authorization_code")
	params.Add("code", code)
	params.Add("redirect_uri", redirectURL)

	err = requests.New(p.RedeemURL.String()).
		WithContext(ctx).
		WithMethod("POST").
		WithBody(bytes.NewBufferString(params.Encode())).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Do().
		UnmarshalInto(&jsonResponse)
	if err != nil {
		return
	}

	created := time.Now()
	expires := time.Unix(jsonResponse.ExpiresIn, 0)

	return &sessions.SessionState{
		AccessToken:  jsonResponse.AccessToken,
		IDToken:      jsonResponse.IDToken,
		CreatedAt:    &created,
		ExpiresOn:    &expires,
		RefreshToken: jsonResponse.RefreshToken,
	}, nil
}

// EnrichSession to add email
func (p *AdfsProvider) EnrichSession(_ context.Context, s *sessions.SessionState) error {
	c, err := adfsClaimsFromToken(s.IDToken)
	if err != nil {
		return err
	}

	s.Email = c.Email
	s.User = c.Upn
	return nil
}

// RefreshSessionIfNeeded checks if the session has expired and uses the
// RefreshToken to fetch a new ID token if required
func (p *AdfsProvider) RefreshSessionIfNeeded(ctx context.Context, s *sessions.SessionState) (bool, error) {
	if s == nil || s.ExpiresOn.After(time.Now()) || s.RefreshToken == "" {
		return false, nil
	}

	origExpiration := s.ExpiresOn

	err := p.redeemRefreshToken(ctx, s)
	if err != nil {
		return false, fmt.Errorf("unable to redeem refresh token: %v", err)
	}

	logger.Printf("refreshed id token %s (expired on %s)\n", s, origExpiration)
	return true, nil
}

func (p *AdfsProvider) redeemRefreshToken(ctx context.Context, s *sessions.SessionState) (err error) {
	params := url.Values{}
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", p.ClientSecret)
	params.Add("refresh_token", s.RefreshToken)
	params.Add("grant_type", "refresh_token")

	var jsonResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in,string"`
		IDToken      string `json:"id_token"`
	}

	err = requests.New(p.RedeemURL.String()).
		WithContext(ctx).
		WithMethod("POST").
		WithBody(bytes.NewBufferString(params.Encode())).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Do().
		UnmarshalInto(&jsonResponse)

	if err != nil {
		return
	}

	now := time.Now()
	expires := time.Unix(jsonResponse.ExpiresIn, 0)
	s.AccessToken = jsonResponse.AccessToken
	s.IDToken = jsonResponse.IDToken
	s.RefreshToken = jsonResponse.RefreshToken
	s.CreatedAt = &now
	s.ExpiresOn = &expires
	return
}

func adfsClaimsFromToken(token string) (*adfsClaims, error) {
	jwt := strings.Split(token, ".")
	if len(jwt) != 3 {
		return nil, fmt.Errorf("failed to parse token, wrong format")
	}
	jwtData := strings.TrimSuffix(jwt[1], "=")
	b, err := base64.RawURLEncoding.DecodeString(jwtData)
	if err != nil {
		return nil, err
	}

	c := &adfsClaims{}
	err = json.Unmarshal(b, c)
	if err != nil {
		return nil, err
	}
	if c.Email == "" {
		c.Email = c.Upn
	}
	return c, nil
}
