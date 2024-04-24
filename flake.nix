{
  description = "Centipede, a work-in-progress multipathing VPN for improving connection reliability and performance for mobile devices and site-to-site connections.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
    crate2nix.url = "github:nix-community/crate2nix";
  };

  outputs = { self, nixpkgs, flake-utils, crate2nix }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        cargoNix = crate2nix.tools.${system}.appliedCargoNix {
          name = "centipede";
          src = ./.;
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
