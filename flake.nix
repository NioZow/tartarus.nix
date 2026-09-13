{
  description = "Tartarus - ad-hoc MicroVMs and containers";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-26.05";
    nixpkgs-unstable.url = "github:nixos/nixpkgs/nixos-unstable";

    home-manager = {
      url = "github:nix-community/home-manager/release-26.05";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    microvm = {
      url = "github:microvm-nix/microvm.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    nix-service = {
      url = "github:niozow/nix-service";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    wprs = {
      url = "github:niozow/wprs";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = inputs @ {self, ...}: import ./nix {inherit inputs self;};
}
