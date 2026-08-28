{
	inputs = {
		nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
		rust-overlay = {
			url = "github:oxalica/rust-overlay";
			inputs.nixpkgs.follows = "nixpkgs";
		};
	};

	outputs = {
		self,
		nixpkgs,
		rust-overlay,
		...
	}: let
		inherit (nixpkgs) lib;
		inherit (lib.attrsets) genAttrs;
		inherit (lib.systems) flakeExposed;
		overlays = [(import rust-overlay)];

		forAllSystems = fn:
			genAttrs flakeExposed (
				system:
					fn (
						import nixpkgs {
							inherit system overlays;
							config.allowUnfree = true;
						}
					)
			);
	in {
		devShells =
			forAllSystems (pkgs: {
					default =
						pkgs.mkShell {
							nativeBuildInputs = with pkgs;
								[
									pkg-config
								]
								++ (lib.lists.optionals stdenv.hostPlatform.isLinux [
										gtk3
										libayatana-appindicator
										libappindicator
									]);
							buildInputs = with pkgs; [
								nixd
								alejandra
								(rust-bin.stable.latest.default.override {
										extensions = ["rust-src" "rust-analyzer"];
									})
							];
							shellHook = with pkgs; (lib.optionalString stdenv.hostPlatform.isLinux ''
									export LD_LIBRARY_PATH="${lib.makeLibraryPath [
											libayatana-appindicator
											libappindicator
										]}:$LD_LIBRARY_PATH"
								'');
						};
				});
	};
}
