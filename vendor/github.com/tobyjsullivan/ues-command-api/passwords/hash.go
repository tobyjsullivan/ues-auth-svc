package passwords

import (
    "errors"
    "fmt"
    "golang.org/x/crypto/scrypt"
)

const (
    HASH_ALGO_SCRYPT_1 = "scrypt.v1"

    SCRYPT_1_HASH_BYTES = 64
    SCRYPT_1_N = 1<<14
    SCRYPT_1_R = 8
    SCRYPT_1_P = 1
)

func scrypt1(password string, salt []byte) ([]byte, error) {
    return scrypt.Key([]byte(password), salt, SCRYPT_1_N, SCRYPT_1_R, SCRYPT_1_P, SCRYPT_1_HASH_BYTES)
}

func Hash(algorithm string, password string, salt []byte) ([]byte, error) {
    switch algorithm {
    case HASH_ALGO_SCRYPT_1:
        return scrypt1(password, salt)
    default:
        return []byte{}, errors.New(fmt.Sprintf("Invalid hash algorithm: %s", algorithm))
    }
}
