package oauth

import (
	"errors"

	"github.com/RichardKnop/go-oauth2-server/password"
	"github.com/RichardKnop/go-oauth2-server/util"
)

var (
	errClientNotFound      = errors.New("Client not found")
	errInvalidClientSecret = errors.New("Invalid client secret")
)

// ClientExists returns true if client exists
func (s *Service) ClientExists(clientID string) bool {
	_, err := s.FindClientByClientID(clientID)
	return err == nil
}

// FindClientByClientID looks up a client by client ID
func (s *Service) FindClientByClientID(clientID string) (*Client, error) {
	// Client IDs are case insensitive
	client := new(Client)
	notFound := s.db.Where("LOWER(key) = LOWER(?)", clientID).
		First(client).RecordNotFound()

	// Not found
	if notFound {
		return nil, errClientNotFound
	}

	return client, nil
}

// CreateClient saves a new client to database
func (s *Service) CreateClient(clientID, secret, redirectURI string) (*Client, error) {
	secretHash, err := password.HashPassword(secret)
	if err != nil {
		return nil, err
	}
	client := &Client{
		Key:         clientID,
		Secret:      string(secretHash),
		RedirectURI: util.StringOrNull(redirectURI),
	}
	if err := s.db.Create(client).Error; err != nil {
		return nil, err
	}
	return client, nil
}

// AuthClient authenticates client
func (s *Service) AuthClient(clientID, secret string) (*Client, error) {
	// Fetch the client
	client, err := s.FindClientByClientID(clientID)
	if err != nil {
		return nil, errClientNotFound
	}

	// Verify the secret
	if password.VerifyPassword(client.Secret, secret) != nil {
		return nil, errInvalidClientSecret
	}

	return client, nil
}
