{
  name = "tunnel";

  nodes = {
    server =
      { config, pkgs, ... }:
      {
        imports = [ ./module.nix ];

        console.keyMap = "colemak";
        services.tunnel = {
          enable = true;
          hostname = "server";
          caddyHostname = "localhost";
          listenPort = 8080;
          caddy.enable = true;
        };

        # Configure Caddy directly
        services.caddy = {
          enable = true;
          logFormat = "level INFO";
          virtualHosts."server" = {
            extraConfig = ''
              reverse_proxy * localhost:8080
            '';
          };
        };

        # Allow tunnel service to bind to privileged ports and manage network
        security.sudo.wheelNeedsPassword = false;
        users.users.tunnel.extraGroups = [ "wheel" ];

        # Disable firewall for testing
        networking.firewall.enable = false;

        # Ensure WireGuard tools are available
        environment.systemPackages = with pkgs; [
          wireguard-go
          wireguard-tools
          nettools
          iproute2
          curl
        ];
      };

    client1 =
      { config, pkgs, ... }:
      {
        console.keyMap = "colemak";
        environment.systemPackages = with pkgs; [
          wireguard-tools
          iproute2
          nettools
          curl
        ];

        # Configure nginx to serve static content
        services.nginx = {
          enable = true;
          virtualHosts."_" = {
            listen = [
              {
                addr = "0.0.0.0";
                port = 8000;
              }
            ];
            locations."/" = {
              root = "/var/www";
              index = "test.txt";
            };
          };
        };

        # Create test file in nginx root
        environment.etc."nginx/test.txt".text = "Hello from client1 via tunnel!";
        systemd.tmpfiles.rules = [
          "d /var/www 0755 nginx nginx -"
          "L+ /var/www/test.txt - - - - /etc/nginx/test.txt"
        ];

        # Disable firewall for testing
        networking.firewall.enable = false;
      };

    client2 =
      { config, pkgs, ... }:
      {
        console.keyMap = "colemak";
        environment.systemPackages = with pkgs; [
          nettools
          curl
        ];

        # Disable firewall for testing
        networking.firewall.enable = false;
      };
  };

  testScript = ''
    import re

    # Start all machines
    start_all()

    # Wait for server to be ready
    server.wait_for_unit("tunnel.service")
    server.wait_for_unit("caddy.service")
    server.wait_for_open_port(8080)
    server.wait_for_open_port(80)

    # Test that tunnel service is responding
    server.succeed("curl -f http://localhost:8080/")

    # Wait for nginx on client1 to be ready
    client1.wait_for_unit("nginx.service")
    client1.wait_for_open_port(8000)

    # Verify nginx is serving the test file locally
    original_content = client1.succeed("curl -s http://localhost:8000/test.txt")
    print(f"Original content: {original_content.strip()}")

    # On client1: Request WireGuard config from tunnel service
    # We need to use the server's IP address since we don't have DNS
    tunnel_config = client1.succeed("curl -f http://server:8080/8000")
    print("Received tunnel config:")
    print(tunnel_config)

    # Write config to file - use a different approach to avoid escaping issues
    client1.succeed("cat > /tmp/tunnel.conf << 'EOF'\n" + tunnel_config + "\nEOF")

    # Extract the slug from the config (from PostUp message)
    slug_match = re.search(r'https://([^.]+)\.server/', tunnel_config)
    if not slug_match:
        raise Exception("Could not find slug in tunnel config")
    slug = slug_match.group(1)
    print(f"Extracted slug: {slug}")

    # Debug: Check if server is reachable at all before WireGuard
    client1.succeed("ping -c 1 server")

    # Bring up the WireGuard tunnel
    client1.succeed("wg-quick up /tmp/tunnel.conf")

    # Wait a moment for the tunnel to establish
    client1.sleep(5)

    # Verify WireGuard interface is up
    wg_output = client1.succeed("wg show")
    print(f"WireGuard status on client1: {wg_output}")

    # Check server WireGuard status  
    server_wg_output = server.succeed("wg show")
    print(f"WireGuard status on server: {server_wg_output}")

    # Debug: Check if client1 can reach server through WireGuard
    client1.succeed("ping -c 1 10.101.0.1")

    # Debug: Check if nginx is accessible locally on client1
    client1.succeed("curl -f http://localhost:8000/test.txt")

    # Debug: Check if nginx is accessible via WireGuard IP on client1
    client1.succeed("curl -f http://10.101.0.2:8000/test.txt")

    # On client2: Access the service through the tunnel
    # First, let's verify the server can resolve the slug
    tunnel_url = f"http://{slug}.server/"
    print(f"Attempting to access: {tunnel_url}")

    # Try to access via the tunnel through Caddy proxy
    # Since we don't have proper DNS, we'll use the server's Caddy as proxy  
    tunneled_content = client2.succeed(f"curl -H 'Host: {slug}.server' http://server/test.txt")
    print(f"Tunneled content: {tunneled_content.strip()}")

    # Verify the content matches
    assert original_content.strip() == tunneled_content.strip(), f"Content mismatch: '{original_content.strip()}' != '{tunneled_content.strip()}'"

    print("SUCCESS: File content matches through tunnel!")

    # Cleanup: bring down the tunnel
    client1.succeed("wg-quick down /tmp/tunnel.conf")

    # Verify tunnel is down (should show empty output)
    wg_down_output = client1.succeed("wg show")
    print(f"WireGuard status after tunnel down: '{wg_down_output.strip()}'")
    assert wg_down_output.strip() == "", f"Expected empty wg show output, got: '{wg_down_output.strip()}'"
  '';
}
