package clients

import (
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	config "xcode/configs"
)

type ClientConnections struct {
	ConnUser *grpc.ClientConn
	ConnCompiler *grpc.ClientConn
}

func InitClients(config *config.Config) (*ClientConnections, error) {
	// Ensure UserGRPCPort includes host:port (e.g., "localhost:50051")
	target := fmt.Sprintf("localhost:%s", config.UserGRPCPort)
	ConnUser, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	fmt.Println("Connecting to UserService at:", target, "ConnUser:", ConnUser)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to User gRPC server: %v", err)
	}

	targetCompiler := fmt.Sprintf("localhost:%s", config.CompilerGRPCPort)
	ConnCompiler, err := grpc.NewClient(targetCompiler, grpc.WithTransportCredentials(insecure.NewCredentials()))
	fmt.Println("Connecting to CompilerService at:", targetCompiler, "ConnCompiler:", ConnCompiler)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Compiler gRPC server: %v", err)
	}

	return &ClientConnections{
		ConnUser: ConnUser,
		ConnCompiler: ConnCompiler,
	}, nil
}

func (c *ClientConnections) Close() {
	if c.ConnUser != nil {
		c.ConnUser.Close()
	}

	if c.ConnCompiler != nil {
		c.ConnCompiler.Close()
	}
}
