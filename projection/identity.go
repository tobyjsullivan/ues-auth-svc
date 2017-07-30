package projection

import (
    "github.com/satori/go.uuid"
    "github.com/tobyjsullivan/ues-command-api/passwords"
    "bytes"
)

type EmailIdentity struct {
    ID uuid.UUID
    Email string
    PasswordHash []byte
    PasswordHashAlgorithm string
    PasswordSalt []byte
}

func (id *EmailIdentity) PasswordMatches(password string) (bool, error) {
    hash, err := passwords.Hash(id.PasswordHashAlgorithm, password, id.PasswordSalt)
    if err != nil {
        return false, err
    }

    hashesMatch := bytes.Compare(hash, id.PasswordHash) == 0

    return hashesMatch, nil
}
