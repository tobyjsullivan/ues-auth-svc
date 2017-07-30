package reader

import (
    "encoding/hex"
)

type Event struct {
    ID EventID
    Log LogID
    Type string
    Data []byte
}

type EventID [32]byte

func (id *EventID) String() string {
    return hex.EncodeToString(id[:])
}

func (id *EventID) Parse(s string) error {
    b, err := hex.DecodeString(s)
    if err != nil {
        return err
    }

    copy(id[:], b)

    return nil
}
