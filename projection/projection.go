package projection

import (
    "github.com/tobyjsullivan/log-sdk/reader"
    "sync"
    "github.com/satori/go.uuid"
    "encoding/json"
    "log"
    "os"
    "encoding/base64"
    "strings"
)

const (
    EVENT_TYPE_ACCOUNT_OPENED = "AccountOpened"
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

    Accounts map[uuid.UUID]*Account
    EmailIdentities map[uuid.UUID]*EmailIdentity

    EmailToEmailIdentityIndex map[string]uuid.UUID
    EmailIdentityToAccountIndex map[uuid.UUID]uuid.UUID
}

func (p *Projection) FindAccount(email string, password string) (*Account, error) {
    normalizedEmail := strings.ToLower(email)

    identityId, ok := p.EmailToEmailIdentityIndex[normalizedEmail]
    if !ok {
        return nil, nil
    }

    identity := p.EmailIdentities[identityId]
    match, err := identity.PasswordMatches(password)
    if err != nil {
        return nil, err
    }
    if !match {
        return nil, nil
    }

    accountId := p.EmailIdentityToAccountIndex[identity.ID]
    account := p.Accounts[accountId]
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

    if _, exists := p.Accounts[accountId]; exists {
        logger.Println("Encountered a duplicate event in handleAccountOpened:", accountId.String())
        return
    }

    p.Accounts[accountId] = &Account{
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

    if _, exists := p.EmailIdentities[identityId]; exists {
        logger.Println("Identity with id already exists.", identityId.String())
        return
    }

    if _, exists := p.Accounts[accountId]; !exists {
        logger.Println("No account with ID exists.", accountId.String())
        return
    }

    identity := &EmailIdentity{
        ID: identityId,
        Email: parsed.Email,
        PasswordHashAlgorithm: parsed.PasswordHashAlgorithm,
        PasswordHash: passwordHash,
        PasswordSalt: passwordSalt,
    }
    p.EmailIdentities[identityId] = identity

    account := p.Accounts[accountId]
    account.Identities = append(account.Identities, identityId)

    p.EmailToEmailIdentityIndex[strings.ToLower(identity.Email)] = identity.ID
    p.EmailIdentityToAccountIndex[identity.ID] = accountId
}


type emailIdentityRegisteredFmt struct {
    IdentityID string `json:"identityId"`
    AccountID string `json:"accountId"`
    Email string `json:"email"`
    PasswordHashAlgorithm string `json:"passwordHashAlgorithm"`
    PasswordHash string `json:"passwordHash"`
    PasswordSalt string `json:"passwordSalt"`
}
