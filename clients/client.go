package clients

import (
	"errors"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	config "xcode/configs"
)

type ClientConnections struct {
	ConnUser       *grpc.ClientConn
	ConnRestaurant *grpc.ClientConn
	ConnAdmin       *grpc.ClientConn
	ConnOrderCart  *grpc.ClientConn
}

func InitClients(config *config.Config) (*ClientConnections, error) {
	// User Service Connection
	ConnUser, err := grpc.NewClient(config.UserGRPCPort, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, errors.New("could not Connect to User gRPC server: " + err.Error())
	}

	return &ClientConnections{
		ConnUser:       ConnUser,
	}, nil
}

func (c *ClientConnections) Close() {
	if c.ConnUser != nil {
		c.ConnUser.Close()
	}
}