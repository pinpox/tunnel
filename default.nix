{ lib
, buildGoModule
, fetchFromGitHub
}:

buildGoModule rec {
  pname = "tunnel";
  version = "unstable";

  src = ./.;

  vendorHash = "sha256-oSI5kPJM3Y4m5py74OSZPDAoeugvkiemRH2uR56+Tco=";

  ldflags = [ "-s" "-w" ];

  # Copy static files
  postInstall = ''
    mkdir -p $out/share/tunnel
    cp -r static $out/share/tunnel/
  '';

  meta = with lib; {
    description = "SSL-terminated HTTP tunnels to your local machine via WireGuard";
    homepage = "https://github.com/pinpox/tunnel";
    license = licenses.gpl3Plus;
    maintainers = [ ];
  };
}