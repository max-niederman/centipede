{
  description = "Centipede, a work-in-progress multipathing VPN for improving connection reliability and performance for mobile devices and site-to-site connections.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
    crate2nix.url = "github:nix-community/crate2nix";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  nixConfig = {
    extra-trusted-public-keys = "eigenvalue.cachix.org-1:ykerQDDa55PGxU25CETy9wF6uVDpadGGXYrFNJA3TUs=";
    extra-substituters = "https://eigenvalue.cachix.org";
    allow-import-from-derivation = true;
  };

  outputs = { self, nixpkgs, flake-utils, crate2nix, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };

        rust = pkgs.rust-bin.selectLatestNightlyWith (toolchain: toolchain.default);

        cargoNixPath = crate2nix.tools.${system}.generatedCargoNix {
          name = "centipede";
          src = ./.;
        };
        cargoNix = import cargoNixPath {
          inherit pkgs;
          buildRustCrateForPkgs = pkgs: pkgs.buildRustCrate.override {
            cargo = rust;
            rustc = rust;
          };
        };
      in
      {
        checks = {
          centipede = cargoNix.workspaceMembers.centipede.build.override {
            runTests = true;
          };
        };

        packages = rec {
          centipede = cargoNix.workspaceMembers.centipede.build;
          default = centipede;
        };
      });
}
