package integration

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"yam/pkg/server"
)

type Client struct {
	baseURL string
	http    *http.Client
}

func NewTestClient(t *testing.T) *Client {
	t.Helper()

	srv := httptest.NewServer(server.NewMux())
	t.Cleanup(srv.Close)

	return &Client{
		baseURL: srv.URL,
		http:    srv.Client(),
	}
}

func (c *Client) Health() (*http.Response, error) {
	return c.http.Get(c.baseURL + "/health")
}
