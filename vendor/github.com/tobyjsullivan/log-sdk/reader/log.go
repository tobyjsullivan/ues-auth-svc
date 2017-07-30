package reader

import "github.com/satori/go.uuid"

type Log struct {
    ID LogID
}

type LogID [16]byte

func (id *LogID) String() string {
    uid := uuid.UUID(*id)
    return uid.String()
}

func (id *LogID) Parse(s string) error {
    uid := uuid.UUID{}
    err := uid.UnmarshalText([]byte(s))
    if err != nil {
        return err
    }

    copy(id[:], uid.Bytes())

    return nil
}
