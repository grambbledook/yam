package store

type ClientStore interface {
	Register(id, secret string, redirectURId, grantTypes, scopes []string) (*Client, error)
	GetClient(id string) (*Client, error)
	Authenticate(id, secret string) (*Client, error)
}
