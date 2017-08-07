package projection

import "github.com/satori/go.uuid"

type Account struct {
	ID         uuid.UUID
	Identities []uuid.UUID
}
