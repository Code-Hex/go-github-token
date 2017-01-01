package token

import (
	"bufio"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/user"

	isatty "github.com/mattn/go-isatty"
	"github.com/octokit/go-octokit/octokit"

	"golang.org/x/crypto/ssh/terminal"
)

const (
	version        = "0.01"
	github         = "github.com"
	createTokenURL = "https://api.github.com/authorizations"
)

var (
	// AppName use to github-access-token's note
	AppName = "go-github-token"
	// UserAgent value
	UserAgent = AppName + " v" + version
	// NoteURL to use github-access-token's note
	NoteURL = "https://github.com/Code-Hex/github-token"
)

// Client is the struct :D
type Client struct {
	Auth       octokit.BasicAuth
	TokenNote  string
	httpClient *http.Client
}

// New will return *token.Client set with http.DefaultClient.
func New() *Client {
	return NewWithClient(http.DefaultClient)
}

// NewWithClient will return *token.Client set with your defined *http.Client.
func NewWithClient(client *http.Client) *Client {
	return &Client{Auth: octokit.BasicAuth{}, httpClient: client}
}

// ReadUsername read username from prompt input.
func (c *Client) ReadUsername() (err error) {
	fmt.Printf("Username for https://%s: ", github)
	c.Auth.Login, err = readline()
	return
}

// ReadPassword read password from prompt input.
func (c *Client) ReadPassword() (err error) {
	if c.Auth.Login == "" {
		return fmt.Errorf("Username is required")
	}

	fmt.Printf("Password for https://%s@%s: ", c.Auth.Login, github)
	stdin := os.Stdin.Fd()
	if isatty.IsTerminal(stdin) {
		var pass []byte
		pass, err = terminal.ReadPassword(int(stdin))
		c.Auth.Password = string(pass)
		fmt.Print("\n")

		return nil
	}

	c.Auth.Password, err = readline()
	return
}

// ReadOTP read two factor authentication code from prompt input.
func (c *Client) ReadOTP() (err error) {
	fmt.Print("two-factor authentication code: ")
	c.Auth.OneTimePassword, err = readline()
	return
}

// GetAccessToken enter the necessary information to obtain the token.
func (c *Client) GetAccessToken() (token string, err error) {
	if err = c.ReadUsername(); err != nil {
		return
	}

	if err = c.ReadPassword(); err != nil {
		return
	}

	for {
		token, err = c.CreateToken()
		if err == nil {
			break
		}

		if ae, ok := err.(*authError); ok && ae.IsRequired2FACode() {
			if c.Auth.OneTimePassword != "" {
				fmt.Println("warning: invalid two-factor code")
			}
			if err = c.ReadOTP(); err != nil {
				return
			}
		} else {
			break
		}
	}

	return
}

// CreateToken create a token based on the information of the *token.Client struct.
func (c *Client) CreateToken() (string, error) {
	octoc := c.newOctokitClient()
	u, _ := url.Parse(createTokenURL)
	authsService := octoc.Authorizations(u)

	authParam := octokit.AuthorizationParams{
		Scopes:  []string{"repo"},
		NoteURL: NoteURL,
	}

	var ae error
	for cnt := 1; cnt < 9; cnt++ {
		if c.TokenNote == "" {
			note, err := tokenNote(cnt)
			if err != nil {
				return "", err
			}
			authParam.Note = note
		} else {
			authParam.Note = c.TokenNote
		}

		auth, result := authsService.Create(authParam)
		if !result.HasError() {
			return auth.Token, nil
		}

		ae = &authError{result.Err}
		if !ae.(*authError).IsDuplicatedToken() {
			return "", ae
		}
	}

	return "", ae
}

// make token note
func tokenNote(cnt int) (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", err
	}

	h, err := os.Hostname()
	if err != nil {
		return "", err
	}

	if cnt > 1 {
		return fmt.Sprintf("%s for %s@%s - %d", AppName, u.Name, h, cnt), nil
	}

	return fmt.Sprintf("%s for %s@%s", AppName, u.Name, h), nil
}

// allow input only by one line
func readline() (line string, err error) {
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		line = scanner.Text()
	}
	err = scanner.Err()
	return
}

// create *octokit.Client
func (c Client) newOctokitClient() *octokit.Client {
	return octokit.NewClientWith(createTokenURL, UserAgent, c.Auth, c.httpClient)
}
