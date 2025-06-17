package natsclient

import (
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
	"go.uber.org/zap"
)

type NatsClient struct {
	Conn *nats.Conn
}

func NewNatsClient(natsURL string, log *zap.Logger) *NatsClient {
	nc, err := nats.Connect(natsURL)
	fmt.Printf("Tried connecting with nats: %v output: %v\n", natsURL, err)
	if err != nil {
		log.Fatal("Failed to create NATS client", zap.String("error", err.Error()))
	}
	log.Info("NATS Client Connected")
	return &NatsClient{Conn: nc}
}

func (n *NatsClient) Close() {
	if n.Conn != nil {
		n.Conn.Close()
	}
}

func (n *NatsClient) Publish(subject string, data []byte) error {
	return n.Conn.Publish(subject, data)
}

func (n *NatsClient) Request(subject string, data []byte, timeout time.Duration) (*nats.Msg, error) {
	return n.Conn.Request(subject, data, timeout)
}

func (n *NatsClient) Subscribe(subject string, handler func(*nats.Msg)) (*nats.Subscription, error) {
	return n.Conn.Subscribe(subject, handler)
}
