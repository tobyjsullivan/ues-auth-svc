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
    "strings"
    "net/url"
    _ "github.com/lib/pq"
    "database/sql"
    "crypto/rand"
    "github.com/satori/go.uuid"
    "encoding/json"
    "encoding/hex"
)

const (
    AUTH_TOKEN_BYTES = 64

    // TODO Read from env var or implement support for multiple clients
    CLIENT_ID = "6C77F4DC179E1575C87F7443EDFCEE6A8C885031CDF1048424DCB4834DF307C5"
    CLIENT_CALLBACK_URL = "http://localhost:3000/callback"
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

    return r
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
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

    if strings.ToUpper(paramClientId) != CLIENT_ID {
        http.Error(w, "Invalid ClientID. "+paramClientId, http.StatusUnauthorized)
        return
    }

    expectedUrl, err := url.Parse(CLIENT_CALLBACK_URL)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    actualUrl, err := url.Parse(paramCallbackUrl)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    if actualUrl.String() != expectedUrl.String() {
        http.Error(w, "Invalid Callback URL.", http.StatusUnauthorized)
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

    err = commitToken(acct.ID, token)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    resp := responseFmt{
        Data: struct{
            Token string `json:"token"`
        }{
            Token: hex.EncodeToString(token),
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

func commitToken(accountId uuid.UUID, token []byte) error {
    res, err := db.Exec(`INSERT INTO Tokens(ACCOUNT_ID, TOKEN) VALUES ($1, $2)`, accountId.Bytes(), token)
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
