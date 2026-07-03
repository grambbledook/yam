package store

type Client struct {
	ID           string
	Secret       string
	RedirectURIs []string
	GrantTypes   []string
	Scopes       []string
}
