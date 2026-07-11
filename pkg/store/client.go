package store

type ClientType string

const (
	Confidential ClientType = "confidential"
	Public       ClientType = "public"
)

type Client struct {
	ID           string
	ClientType   ClientType
	Secret       string
	RedirectURIs []string
	GrantTypes   []string
	Scopes       []string
}
