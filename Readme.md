# xcode - Competitive Programming Platform

A comprehensive LeetCode-style coding platform built with microservices architecture, enabling users to solve coding challenges, compile code in multiple languages, and participate in competitive programming. The platform features real-time code execution, problem management, user authentication, and live coding challenges.

**zenx** is the overall project name, while **xcode** refers to the backend microservices collectively.

**Live Platform:** [zenxbattle.space](https://zenxbattle.space)  
**Frontend Repository:** [zenxfrontend](https://github.com/lijuuu/zenxfrontend)

## Getting Started

Each service in the xcode platform is designed to be independently deployable and maintainable. For detailed setup instructions, deployment procedures, and configuration options, please refer to the individual service repositories listed below.

### Recommended Deployment Order

1. **Auth & User Service** - Core authentication and user management
2. **Problem Service** - Problem repository and management
3. **Code Engine** - Code compilation and execution
4. **Challenge WebSocket Manager** - Real-time challenge features
5. **API Gateway** - Central routing and request handling

### API Gateway Deployment

This repository includes a Docker configuration for API Gateway deployment:

```bash
# Build the API Gateway image
docker build -t api-gateway .

# Run the API Gateway container
docker run -p 8080:8080 --env-file .env api-gateway
```

The API Gateway serves as the entry point for client requests and routes them to appropriate microservices.

## System Architecture

### Microservices Overview

| Service | Repository | Description | Self-Host Documentation | Environment Example |
|---------|------------|-------------|------------------------|-------------------|
| **API Gateway** | [xcodeApiGateway](https://github.com/lijuuu/xcodeApiGateway) | Central routing and request handling gateway | [Setup Guide](https://github.com/lijuuu/xcodeApiGateway#readme) | [.env.example](https://github.com/lijuuu/xcodeApiGateway/blob/main/.env.example) |
| **Code Engine** | [xcodeEngine](https://github.com/lijuuu/xcodeEngine) | Core code execution and compilation service | [Setup Guide](https://github.com/lijuuu/xcodeEngine#readme) | [.env.example](https://github.com/lijuuu/xcodeEngine/blob/main/.env.example) |
| **Problem Service** | [xcodeProblemService](https://github.com/lijuuu/xcodeProblemService) | Manages coding problems and challenges | [Setup Guide](https://github.com/lijuuu/xcodeProblemService#readme) | [.env.example](https://github.com/lijuuu/xcodeProblemService/blob/main/.env.example) |
| **Auth & User Service** | [xcodeAuthUserAdminService](https://github.com/lijuuu/xcodeAuthUserAdminService) | Authentication, user management, and admin operations | [Setup Guide](https://github.com/lijuuu/xcodeAuthUserAdminService#readme) | [.env.example](https://github.com/lijuuu/xcodeAuthUserAdminService/blob/main/.env.example) |
| **Challenge WebSocket Manager** | [ChallengeWssManagerService](https://github.com/lijuuu/ChallengeWssManagerService) | Real-time challenge management and WebSocket connections | [Setup Guide](https://github.com/lijuuu/ChallengeWssManagerService#readme) | [.env.example](https://github.com/lijuuu/ChallengeWssManagerService/blob/main/.env.example) |

### Service Dependencies

The services communicate with each other through:
- **gRPC** for high-performance service-to-service communication using shared proto definitions
- **NATS messaging** for asynchronous communication
- **REST APIs** for synchronous operations
- **WebSocket connections** for real-time features

#### gRPC Communication

All services use **gRPC** for efficient, type-safe inter-service communication. The platform leverages a centralized proto definition repository:

- **Proto Repository**: [GlobalProtoXcode](https://github.com/lijuuu/GlobalProtoXcode)
- **Generated Stubs**: Available as Go module via `go get github.com/lijuuu/GlobalProtoXcode`
- **Service Contracts**: Shared proto definitions ensure consistent APIs across all microservices
- **Type Safety**: Strongly typed service interfaces with automatic code generation

## Features

- **Problem Solving:** Browse and solve coding problems across multiple difficulty levels
- **Multi-Language Support:** Code compilation and execution for Go, Python, and JavaScript
- **Real-time Challenges:** Live coding competitions with WebSocket-based real-time updates
- **User Management:** Comprehensive authentication and user profile system
- **Leaderboards:** High-performance Redis-based leaderboards using [RedisBoard](https://github.com/lijuuu/RedisBoard) for real-time ranking and competitive tracking
- **Code Editor:** In-browser code editor with syntax highlighting
- **Test Cases:** Automated testing with predefined test cases
- **Admin Panel:** Manage problems, challenges, and user accounts
- **Dockerized:** Easy deployment and scaling with Docker


## API Documentation (to be updated)

### Service Endpoints

Each service exposes its own API endpoints:

- **Auth Service**: User authentication and management
- **Problem Service**: CRUD operations for coding problems
- **Code Engine**: Code compilation and execution
- **Challenge Manager**: Real-time challenge coordination

*For detailed API documentation, refer to individual service repositories.*

## Architecture Details

### Technology Stack

- **Backend:** Go (Gin framework)
- **Caching:** Ristretto (Token Invalidation)
- **Authentication:** JWT
- **Logging:** Zap with BetterStack integration
- **Containerization:** Docker

### Key Features

- **Microservices Architecture:** Scalable and maintainable service separation
- **Real-time Communication:** WebSocket support for live challenges
- **Code Execution:** Secure sandboxed code compilation and execution
- **Distributed Messaging:** NATS-based inter-service communication
- **Comprehensive Logging:** Structured logging with external monitoring
- **JWT Authentication:** Secure token-based authentication

## Contributing

1. Fork the relevant repository
2. Create a feature branch (`git checkout -b feature/new-feature`)
3. Commit your changes (`git commit -m 'Add some new feature'`)
4. Push to the branch (`git push origin feature/new-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Related Repositories

- [Code Engine Service](https://github.com/lijuuu/xcodeEngine)
- [Problem Management Service](https://github.com/lijuuu/xcodeProblemService)
- [Authentication & User Service](https://github.com/lijuuu/xcodeAuthUserAdminService)
- [Challenge WebSocket Manager](https://github.com/lijuuu/ChallengeWssManagerService)

## Support

For support and questions:
- Create an issue in the relevant repository
- Contact the development team

---

**Note:** This README provides an overview of the entire ZenX platform. For service-specific setup instructions and deployment procedures, please refer to individual repository documentation linked above.
