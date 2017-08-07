package projection

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/satori/go.uuid"
	"github.com/tobyjsullivan/log-sdk/reader"
)

const (
	EVENT_TYPE_ACCOUNT_OPENED            = "AccountOpened"
	EVENT_TYPE_EMAIL_IDENTITY_REGISTERED = "EmailIdentityRegistered"
)

var (
	logger *log.Logger
)

func init() {
	logger = log.New(os.Stdout, "[projection] ", 0)
}

type Projection struct {
	mx sync.Mutex

	accounts        map[uuid.UUID]*Account
	emailIdentities map[uuid.UUID]*EmailIdentity

	emailToEmailIdentityIndex   map[string]uuid.UUID
	emailIdentityToAccountIndex map[uuid.UUID]uuid.UUID
}

func NewProjection() *Projection {
	return &Projection{
		accounts:                    make(map[uuid.UUID]*Account),
		emailIdentities:             make(map[uuid.UUID]*EmailIdentity),
		emailToEmailIdentityIndex:   make(map[string]uuid.UUID),
		emailIdentityToAccountIndex: make(map[uuid.UUID]uuid.UUID),
	}
}

func (p *Projection) FindAccount(email string, password string) (*Account, error) {
	normalizedEmail := strings.ToLower(email)

	identityId, ok := p.emailToEmailIdentityIndex[normalizedEmail]
	if !ok {
		return nil, nil
	}

	identity := p.emailIdentities[identityId]
	match, err := identity.PasswordMatches(password)
	if err != nil {
		return nil, err
	}
	if !match {
		return nil, nil
	}

	accountId := p.emailIdentityToAccountIndex[identity.ID]
	account := p.accounts[accountId]
	return account, nil
}

func (p *Projection) Apply(e *reader.Event) {
	p.mx.Lock()
	defer p.mx.Unlock()

	switch e.Type {
	case EVENT_TYPE_ACCOUNT_OPENED:
		p.handleAccountOpened(e.Data)
	case EVENT_TYPE_EMAIL_IDENTITY_REGISTERED:
		p.handleEmailIdentityRegistered(e.Data)
	}
}

func (p *Projection) handleAccountOpened(data []byte) {
	var parsed accountOpenedFmt
	err := json.Unmarshal(data, &parsed)
	if err != nil {
		logger.Println("Error parsing event in handleAccountOpened.", err.Error())
		return
	}

	accountId := uuid.UUID{}
	err = accountId.UnmarshalText([]byte(parsed.AccountID))
	if err != nil {
		logger.Println("Error parsing accountId in handleAccountOpened.", err.Error())
		return
	}

	if _, exists := p.accounts[accountId]; exists {
		logger.Println("Encountered a duplicate event in handleAccountOpened:", accountId.String())
		return
	}

	p.accounts[accountId] = &Account{
		ID: accountId,
	}
}

type accountOpenedFmt struct {
	AccountID string `json:"accountId"`
}

func (p *Projection) handleEmailIdentityRegistered(data []byte) {
	var parsed emailIdentityRegisteredFmt
	if err := json.Unmarshal(data, &parsed); err != nil {
		logger.Println("Error parsing event in handleEmailIdentityRegistered.", err.Error())
		return
	}

	identityId := uuid.UUID{}
	if err := identityId.UnmarshalText([]byte(parsed.IdentityID)); err != nil {
		logger.Println("Error parsing identityId in handleEmailIdentityRegistered.", err.Error())
		return
	}

	accountId := uuid.UUID{}
	if err := accountId.UnmarshalText([]byte(parsed.AccountID)); err != nil {
		logger.Println("Error parsing accountId in handleEmailIdentityRegistered.", err.Error())
		return
	}

	passwordHash, err := base64.StdEncoding.DecodeString(parsed.PasswordHash)
	if err != nil {
		logger.Println("Error parsing passwordHash in handleEmailIdentityRegistered.", err.Error())
		return
	}

	passwordSalt, err := base64.StdEncoding.DecodeString(parsed.PasswordSalt)
	if err != nil {
		logger.Println("Error parsing passwordSalt in handleEmailIdentityRegistered.", err.Error())
		return
	}

	if _, exists := p.emailIdentities[identityId]; exists {
		logger.Println("Identity with id already exists.", identityId.String())
		return
	}

	if _, exists := p.accounts[accountId]; !exists {
		logger.Println("No account with ID exists.", accountId.String())
		return
	}

	identity := &EmailIdentity{
		ID:    identityId,
		Email: parsed.Email,
		PasswordHashAlgorithm: parsed.PasswordHashAlgorithm,
		PasswordHash:          passwordHash,
		PasswordSalt:          passwordSalt,
	}
	p.emailIdentities[identityId] = identity

	account := p.accounts[accountId]
	account.Identities = append(account.Identities, identityId)

	p.emailToEmailIdentityIndex[strings.ToLower(identity.Email)] = identity.ID
	p.emailIdentityToAccountIndex[identity.ID] = accountId
}

type emailIdentityRegisteredFmt struct {
	IdentityID            string `json:"identityId"`
	AccountID             string `json:"accountId"`
	Email                 string `json:"email"`
	PasswordHashAlgorithm string `json:"passwordHashAlgorithm"`
	PasswordHash          string `json:"passwordHash"`
	PasswordSalt          string `json:"passwordSalt"`
}
