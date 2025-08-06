{
  description = "tunnel";

  # Nixpkgs / NixOS version to use.
  inputs.nixpkgs.url = "nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let

      # to work with older version of flakes
      lastModifiedDate = self.lastModifiedDate or self.lastModified or "19700101";

      # Generate a user-friendly version number.
      version = builtins.substring 0 8 lastModifiedDate;

      # System types to support.
      supportedSystems = [ "x86_64-linux" "x86_64-darwin" "aarch64-linux" "aarch64-darwin" ];

      # Helper function to generate an attrset '{ x86_64-linux = f "x86_64-linux"; ... }'.
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;

      # Nixpkgs instantiated for supported system types.
      nixpkgsFor = forAllSystems (system: import nixpkgs { inherit system; });

    in
    {

      # Provide some binary packages for selected system types.
      packages = forAllSystems (system:
        let
          pkgs = nixpkgsFor.${system};
        in
        {
          default = pkgs.callPackage ./default.nix {};
          tunnel = pkgs.callPackage ./default.nix {};
        });

      # NixOS module
      nixosModules.default = import ./module.nix;
      nixosModules.tunnel = import ./module.nix;

      # NixOS test
      checks = forAllSystems (system:
        let
          pkgs = nixpkgsFor.${system};
        in
        {
          tunnel-test = pkgs.testers.runNixOSTest (import ./test.nix);
        });

      # Development shell
      devShells = forAllSystems (system:
        let
          pkgs = nixpkgsFor.${system};
        in
        {
          default = pkgs.mkShell {
            buildInputs = with pkgs; [
              go
              wireguard-tools
              caddy
              curl
            ];
          };
        });

    };
}
