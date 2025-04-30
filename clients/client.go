package clients

import (
	"fmt"
	"time"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/connectivity"
	config "xcode/configs"
)

type ClientConnections struct {
	ConnUser    *grpc.ClientConn
	ConnProblem *grpc.ClientConn
}

func InitClients(config *config.Config) (*ClientConnections, error) {
	// Ensure the UserGRPCURL includes full URL (e.g., "localhost:50051")
	targetUser := config.UserGRPCURL
	ConnUser, err := grpc.Dial(targetUser, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to User gRPC server: %v", err)
	}
	// Wait for the connection to be ready (timeout after 5 seconds)
	if err := waitForConnection(ConnUser); err != nil {
		return nil, fmt.Errorf("failed to connect to User service: %v", err)
	}
	fmt.Println("Successfully connected to UserService at:", targetUser)

	targetProblem := config.ProblemGRPCURL
	ConnProblem, err := grpc.Dial(targetProblem, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Problem gRPC server: %v", err)
	}
	// Wait for the connection to be ready (timeout after 5 seconds)
	if err := waitForConnection(ConnProblem); err != nil {
		return nil, fmt.Errorf("failed to connect to Problem service: %v", err)
	}
	fmt.Println("Successfully connected to ProblemService at:", targetProblem)

	return &ClientConnections{
		ConnUser:    ConnUser,
		ConnProblem: ConnProblem,
	}, nil
}

// waitForConnection checks the state of the connection and waits until it's ready or times out.
func waitForConnection(conn *grpc.ClientConn) error {
	// Set a timeout for waiting for the connection to become ready
	timeout := time.After(5 * time.Second)
	for {
		select {
		case <-timeout:
			return fmt.Errorf("timeout waiting for gRPC connection to become ready")
		default:
			// Check the state of the connection
			state := conn.GetState()
			if state == connectivity.Ready {
				return nil // Connection is ready
			}
			// Wait a bit before checking again
			time.Sleep(500 * time.Millisecond)
		}
	}
}

func (c *ClientConnections) Close() {
	if c.ConnUser != nil {
		c.ConnUser.Close()
	}

	if c.ConnProblem != nil {
		c.ConnProblem.Close()
	}
}
