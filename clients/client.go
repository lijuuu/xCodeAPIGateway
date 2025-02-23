package clients

import (
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	config "xcode/configs"
)

type ClientConnections struct {
	ConnUser *grpc.ClientConn
}

func InitClients(config *config.Config) (*ClientConnections, error) {
	// Ensure UserGRPCPort includes host:port (e.g., "localhost:50051")
	target := fmt.Sprintf("localhost:%s", config.UserGRPCPort)
	ConnUser, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	fmt.Println("Connecting to UserService at:", target, "ConnUser:", ConnUser)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to User gRPC server: %v", err)
	}

	return &ClientConnections{
		ConnUser: ConnUser,
	}, nil
}

func (c *ClientConnections) Close() {
	if c.ConnUser != nil {
		c.ConnUser.Close()
	}
}
