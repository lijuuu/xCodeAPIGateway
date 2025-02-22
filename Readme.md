# Protobuf Compilation with Go

This project provides a Makefile for installing necessary tools and generating gRPC code from Protocol Buffers (protobuf) files.

## Prerequisites

Before using the Makefile, ensure you have the following installed:

- Go (version 1.16 or later)
- Protocol Buffers Compiler (`protoc`)

## Setting Up Your Environment

1. **Set the GOPATH**: Make sure to set your `GOPATH` environment variable. You can do this by adding the following lines to your shell configuration file (e.g., `.bashrc`, `.bash_profile`, or `.zshrc`):

   ```bash
   export GOPATH=$HOME/go
   export PATH=$PATH:$GOPATH/bin
   ```

   After adding these lines, run `source ~/.bashrc` (or the appropriate file) to apply the changes.

2. **Verify the Environment**: Check that your `GOPATH` is set correctly:

   ```bash
   echo $GOPATH
   ```

   This should output the path you set (e.g., `/home/yourusername/go`).

## Adding the Submodule

To include the `CentralisedFoodbuddyMicroserviceProto` repository as a submodule in your project, run the following command in your project directory:

```bash
git submodule add https://github.com/liju-github/CentralisedFoodbuddyMicroserviceProto
```

After adding the submodule, initialize and update it:

```bash
git submodule init
git submodule update
```

## Usage

To initialize the environment, install necessary tools, and generate gRPC code, run the following command in the project directory:

```bash
make all
```

### Example

1. **Define a Proto File**: Create a file named `user.proto` in the `UserService` directory with the following content:

   ```proto
   syntax = "proto3";

   package userservice;

   service UserService {
       rpc GetUser (UserRequest) returns (UserResponse);
   }

   message UserRequest {
       string id = 1;
   }

   message UserResponse {
       string id = 1;
       string name = 2;
       string email = 3;
   }
   ```

2. **Generate Go Code**: After defining your proto file, run the following command to generate the Go code:

   ```bash
   make all
   ```

3. **Check Generated Files**: The generated Go files will be located in the `UserService` directory. You can now implement the server and client logic using the generated code.

### Targets

- `init`: Initializes the environment and checks if `GO_MODULE` is set.
- `install-tools`: Installs the required Go tools for protobuf compilation.
- `generate-proto`: Generates gRPC code from the proto files located in the specified directories.
- `tidy`: Cleans up the Go module dependencies.

## Troubleshooting

If you encounter issues with the `protoc-gen-go` or `protoc-gen-go-grpc` not being found, ensure that your `GOPATH` is set correctly and that the Go binaries are in your `PATH`.

## License

This project is licensed under the MIT License.
