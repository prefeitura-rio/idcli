{
  description = "idcli Development Environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          config = {
            allowUnfree = true;
          };
        };
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            go
            gopls
            go-tools
            just
            docker
            docker-compose
            gotools  # Includes swag
          ];

          shellHook = ''
            echo "idcli Development Environment"
            echo "Available tools:"
            echo "- Go $(go version)"
            echo "- Just $(just --version)"
            echo "- Docker $(docker --version)"
            echo ""
            echo "To see available commands, run: just"

            # Add GOBIN to PATH
            export GOBIN="$PWD/bin"
            export PATH="$GOBIN:$PATH"
          '';
        };
      }
    );
} 