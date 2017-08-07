package main

import (
    "os"

    "fmt"
    "net/http"

    "github.com/urfave/negroni"
    "github.com/gorilla/mux"
    "github.com/tobyjsullivan/ues-auth-svc/projection"
    "github.com/tobyjsullivan/log-sdk/reader"
    "log"
    "net/url"
    _ "github.com/lib/pq"
    "database/sql"
    "crypto/rand"
    "github.com/satori/go.uuid"
    "encoding/json"
    "encoding/hex"
    "time"
    "errors"
    "encoding/base64"
    "bytes"
)

const (
    AUTH_TOKEN_BYTES = 64
    AUTH_TOKEN_EXPIRY_SECONDS = 86400 // 24 hours
)

var (
    logger *log.Logger
    db         *sql.DB
    logId reader.LogID
    client *reader.Client
    state *projection.Projection
)

func init() {
    logger = log.New(os.Stdout, "[service] ", 0)

    pgHostname := os.Getenv("PG_HOSTNAME")
    pgUsername := os.Getenv("PG_USERNAME")
    pgPassword := os.Getenv("PG_PASSWORD")
    pgDatabase := os.Getenv("PG_DATABASE")

    dbConnOpts := fmt.Sprintf("host='%s' user='%s' dbname='%s' password='%s' sslmode=disable",
        pgHostname, pgUsername, pgDatabase, pgPassword)

    logger.Println("Connecting to DB...")
    var err error
    db, err = sql.Open("postgres", dbConnOpts)
    if err != nil {
        logger.Println("Error initializing connection to Postgres DB.", err.Error())
        panic(err.Error())
    }

    readerSvc := os.Getenv("LOG_READER_API")

    client, err = reader.New(&reader.ClientConfig{
        ServiceAddress: readerSvc,
        Logger: logger,
    })
    if err != nil {
        panic("Error creating reader client. " + err.Error())
    }

    logId = reader.LogID{}
    err = logId.Parse(os.Getenv("SERVICE_LOG_ID"))
    if err != nil {
        panic("Error parsing LogID. "+err.Error())
    }

    err = client.ValidateLog(logId)
    if err != nil {
        panic("Log validation failed. "+err.Error())
    }

    state = projection.NewProjection()

    logger.Println("Subscribing projection to log.", logId.String())

    start := reader.EventID{}
    client.Subscribe(logId, start, state.Apply, true)

    logger.Println("Hydration complete.", logId.String())
}

func main() {
    r := buildRoutes()

    n := negroni.New()
    n.UseHandler(r)

    port := os.Getenv("PORT")
    if port == "" {
        port = "3000"
    }

    n.Run(":" + port)
}

func buildRoutes() http.Handler {
    r := mux.NewRouter()
    r.HandleFunc("/", statusHandler).Methods("GET")
    r.HandleFunc("/authorize", authHandler).Methods("POST")
    r.HandleFunc("/verify", verifyTokenHandler).Methods("POST")

    return r
}

func statusHandler(w http.ResponseWriter, _ *http.Request) {
    fmt.Fprint(w, "The ues-auth-svc service is online!\n")
}

func authHandler(w http.ResponseWriter, r *http.Request) {
    if err := r.ParseForm(); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    paramEmail := r.Form.Get("email")
    paramPassword := r.Form.Get("password")
    paramClientId := r.Form.Get("client-id")
    paramCallbackUrl := r.Form.Get("callback")

    if paramEmail == "" {
        http.Error(w, "Must provide email.", http.StatusBadRequest)
        return
    }

    if paramPassword == "" {
        http.Error(w, "Must provide password.", http.StatusBadRequest)
        return
    }

    if paramClientId == "" {
        http.Error(w, "Must provide client-id.", http.StatusBadRequest)
        return
    }

    if paramCallbackUrl == "" {
        http.Error(w, "Must provide callback.", http.StatusBadRequest)
        return
    }

    clientId, err := parseClientId(paramClientId)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    callbackUrl, err := url.Parse(paramCallbackUrl)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    valid, err := validateClientCallbackUrl(clientId, callbackUrl)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    } else if !valid {
        http.Error(w, "Invalid client-id or callback-url.", http.StatusUnauthorized)
        return
    }

    acct, err := state.FindAccount(paramEmail, paramPassword)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    if acct == nil {
        http.Error(w, "Account not found.", http.StatusUnauthorized)
        return
    }

    // Generate an auth token
    token := make([]byte, AUTH_TOKEN_BYTES)
    _, err = rand.Read(token)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    expiry := time.Now().Add(AUTH_TOKEN_EXPIRY_SECONDS * time.Second)

    t := &tokenIssue{
        clientId: clientId,
        accountId: acct.ID,
        token: token,
        expiry: expiry,
    }

    err = commitToken(t)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    timeToExpire := expiry.Sub(time.Now())

    resp := responseFmt{
        Data: struct{
            Token string `json:"token"`
            Expires int `json:"expires"`
        }{
            Token: hex.EncodeToString(token),
            Expires: int(timeToExpire.Seconds()),
        },
    }

    encoder := json.NewEncoder(w)
    if err = encoder.Encode(&resp); err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
}

func verifyTokenHandler(w http.ResponseWriter, r *http.Request) {
    if err := r.ParseForm(); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    paramToken := r.Form.Get("token")
    paramClientId := r.Form.Get("client-id")
    paramClientSecret := r.Form.Get("client-secret")

    clientId, err := parseClientId(paramClientId)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    clientSecret, err := base64.StdEncoding.DecodeString(paramClientSecret)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    valid, err := validateClientSecret(clientId, clientSecret)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    } else if !valid {
        http.Error(w, "Invalid client-id or client-secret.", http.StatusUnauthorized)
        return
    }

    token, err := hex.DecodeString(paramToken)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    issue, err := lookupToken(clientId, token)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    timeToExpire := issue.expiry.Sub(time.Now())

    resp := responseFmt{
        Data: struct {
            AccountID string `json:"accountId"`
            Expires int `json:"expires"`
        }{
            AccountID: issue.accountId.String(),
            Expires: int(timeToExpire.Seconds()),
        },
    }

    encoder := json.NewEncoder(w)
    if err = encoder.Encode(&resp); err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
}

type responseFmt struct {
    Data interface{} `json:"data"`
}

func parseClientId(s string) ([32]byte, error) {
    bytesClientId, err := hex.DecodeString(s)
    if err != nil {
        return [32]byte{}, err
    }

    var clientId [32]byte
    copy(clientId[:], bytesClientId)

    return clientId, nil
}

func validateClientCallbackUrl(clientId [32]byte, callbackUrl *url.URL) (bool, error) {
    if callbackUrl == nil {
        return false, errors.New("No callbackUrl value present")
    }

    expectedId, err := parseClientId(os.Getenv("CLIENT_ID"))
    if err != nil {
        return false, err
    }

    expectedUrl, err := url.Parse(os.Getenv("CLIENT_CALLBACK_URL"))
    if err != nil {
        return false, err
    }

    return clientId == expectedId && callbackUrl.String() == expectedUrl.String(), nil
}

func validateClientSecret(clientId [32]byte, clientSecret []byte) (bool, error) {
    expectedId, err := parseClientId(os.Getenv("CLIENT_ID"))
    if err != nil {
        return false, err
    }

    expectedSecret, err := base64.StdEncoding.DecodeString(os.Getenv("CLIENT_SECRET"))
    if err != nil {
        return false, err
    }

    return clientId == expectedId && bytes.Equal(clientSecret, expectedSecret), nil
}

func commitToken(t *tokenIssue) error {
    // TODO Add Client-ID to record
    res, err := db.Exec(`INSERT INTO Tokens(ACCOUNT_ID, TOKEN, EXPIRES) VALUES ($1, $2, $3)`, t.accountId.Bytes(), t.token, t.expiry)
    if err != nil {
        logger.Println("Error inserting new log record.", err.Error())
        return err
    }

    numRows, err := res.RowsAffected()
    if err != nil {
        logger.Println("Error reading RowsAffected.", err.Error())
        return err
    }
    logger.Println("Rows affected:", numRows)

    return nil
}

func lookupToken(clientId [32]byte, token []byte) (*tokenIssue, error) {
    // TODO Add clientID filter to where clause
    var accountIdBytes []byte
    var expires time.Time
    err := db.QueryRow(`SELECT ACCOUNT_ID, EXPIRES FROM Tokens WHERE token=$1 AND expires>NOW()`, token).Scan(&accountIdBytes, &expires)
    if err != nil {
        return nil, err
    }

    accountId := uuid.UUID{}
    copy(accountId[:], accountIdBytes)

    return &tokenIssue{
        clientId: clientId,
        accountId: accountId,
        token: token,
        expiry: expires,
    }, nil
}


type tokenIssue struct {
    clientId [32]byte
    accountId uuid.UUID
    token []byte
    expiry time.Time
}
