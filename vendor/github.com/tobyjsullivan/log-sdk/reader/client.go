package reader

import (
    "net/url"
    "fmt"
    "net/http"
    "encoding/json"
    "encoding/base64"
    "time"
    "log"
    "context"
    "errors"
)

type Client struct {
    serviceUrl    *url.URL
    subscriptions []*subscription
    logger        *log.Logger
}

type ClientConfig struct {
    ServiceAddress string
    Logger *log.Logger
}

func New(config *ClientConfig) (*Client, error) {
    svcUrl, err := url.Parse(config.ServiceAddress)
    if err != nil {
        return nil, err
    }

    return &Client{
        serviceUrl: svcUrl,
        logger: config.Logger,
    }, nil
}

func (c *Client) logLn(v ...interface{}) {
    if c.logger != nil {
        c.logger.Println(v...)
    }
}

func (c *Client) ValidateLog(logId LogID) error {
    endpoint := c.serviceUrl.ResolveReference(&url.URL{
        Path: fmt.Sprintf("/logs/%s", logId.String()),
    })

    resp, err := http.Get(endpoint.String())
    if err != nil {
        return err
    }

    if resp.StatusCode != http.StatusOK {
        return errors.New("Unexpected response code looking up log: "+resp.Status)
    }

    return nil
}

func (c *Client) GetEvents(logId LogID, after EventID) ([]*Event, error) {
    endpoint := c.serviceUrl.ResolveReference(&url.URL{
        Path: fmt.Sprintf("/logs/%s/events", logId.String()),
    })


    q := endpoint.Query()
    q.Set("after", after.String())
    endpoint.RawQuery = q.Encode()

    resp, err := http.Get(endpoint.String())
    if err != nil {
        return []*Event{}, err
    }
    defer resp.Body.Close()

    var parsed eventsResponseFmt
    decoder := json.NewDecoder(resp.Body)
    err = decoder.Decode(&parsed)
    if err != nil {
        return []*Event{}, err
    }

    events := make([]*Event, len(parsed.Data.Events))
    for i, e := range parsed.Data.Events {
        id := EventID{}
        err := id.Parse(e.EventID)
        if err != nil {
            return []*Event{}, err
        }

        data, err := base64.StdEncoding.DecodeString(e.Data)
        if err != nil {
            return []*Event{}, err
        }

        events[i] = &Event{
            ID: id,
            Log: logId,
            Type: e.Type,
            Data: data,
        }
    }

    return events, nil
}

func (c *Client) Subscribe(logId LogID, after EventID, onEventCommitted func (*Event), hydrate bool) context.CancelFunc {
    ctx, cancel := context.WithCancel(context.Background())

    sub := &subscription{
        logId: logId,
        previousEvent: after,
        onEventCommitted: onEventCommitted,
    }

    if hydrate {
        sub.previousEvent = c.processEvents(logId, after, sub.onEventCommitted)
    }

    c.subscriptions = append(c.subscriptions, sub)

    go sub.runPollLoop(ctx, c)

    return cancel
}

type subscription struct {
    logId LogID
    onEventCommitted func(*Event)
    previousEvent EventID
}

func (sub *subscription) runPollLoop(ctx context.Context, c *Client) {
    t := time.Tick(100 * time.Millisecond)
    for {
        select {
        case <-t:
            sub.previousEvent = c.processEvents(sub.logId, sub.previousEvent, sub.onEventCommitted)
        case <-ctx.Done():
            return
        }
    }
}

func (c *Client) processEvents(logId LogID, after EventID, callback func (*Event)) EventID {
    events, err := c.GetEvents(logId, after)
    if err != nil {
        c.logLn("Error fetching events for subscription.", err.Error())
        return after
    }

    if num := len(events); num > 0 {
        c.logLn(fmt.Sprintf("Found %d new events", num))
    }

    lastEvent := after
    for _, e := range events {
        c.logLn("Event found:", e.ID.String())
        callback(e)
        lastEvent = e.ID
    }
    return lastEvent
}

type eventsResponseFmt struct {
    Data *struct{
        Events []*struct {
            EventID string `json:"eventId"`
            Type string `json:"type"`
            Data string `json:"data"`
        } `json:"events"`
    } `json:"data"`
}

type EventResult struct {
    Event *Event
    Error error
}
