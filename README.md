# tunnel

`tunnel` can be used as an ephemeral reverse proxy for your local
services. This may be useful, for instance when you need to show your friend
something cool you've built.

`tunnel` works without installing any software on your machine,
thanks to the magic of Wireguard.

## Usage

To start a tunnel for your local service on port 8080

```sh
# Remember to bind your local service to 0.0.0.0
curl https://your-tunnel-domain.com/8080 > tunnel.conf && wg-quick up ./tunnel.conf
```

To stop your tunnel

```sh
wg-quick down ./tunnel.conf
```

## Self-hosting

The recommended way of self-hosting is using the provided NixOS module. On other
distributions you will need to compile the binary, provide `wireguard`,
`wireguard-tools` and `caddy` and set up a systemd service A example systemd
service file is included in the repository.

## Acknowledgments

This is a Go re-implementation of the original
[tunnel.pyjam.as](https://gitlab.com/pyjam.as/tunnel) project by Carl Bordum
Hansen and Asbjørn Kofoed-Nielsen. Thanks to the original authors for the
brilliant concept and implementation.

