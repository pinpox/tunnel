{
  config,
  lib,
  pkgs,
  ...
}:

with lib;

let
  cfg = config.services.tunnel;
in
{
  options.services.tunnel = {
    enable = mkEnableOption "tunnel service";

    package = mkOption {
      type = types.package;
      description = "The tunnel package to use";
    };

    hostname = mkOption {
      type = types.str;
      default = "tunnel.localhost";
      example = "tunnel.example.com";
      description = "The hostname for the tunnel service";
    };

    caddyHostname = mkOption {
      type = types.str;
      default = "localhost";
      description = "The hostname where Caddy is running";
    };

    wireguardInterface = mkOption {
      type = types.str;
      default = "tunnel";
      description = "The name of the WireGuard interface";
    };

    wireguardNetwork = mkOption {
      type = types.str;
      default = "10.101.0.0/16";
      description = "The WireGuard network CIDR";
    };

    wireguardPort = mkOption {
      type = types.port;
      default = 54321;
      description = "The WireGuard listen port";
    };

    listenPort = mkOption {
      type = types.port;
      default = 8080;
      description = "The port for the tunnel HTTP service";
    };

    caddy = {
      enable = mkEnableOption "Caddy reverse proxy integration";
    };

    user = mkOption {
      type = types.str;
      default = "tunnel";
      description = "User account under which tunnel runs";
    };

    group = mkOption {
      type = types.str;
      default = "tunnel";
      description = "Group under which tunnel runs";
    };
  };

  config = mkIf cfg.enable {
    # Create user and group
    users.users.${cfg.user} = {
      group = cfg.group;
      isSystemUser = true;
      description = "Tunnel service user";
    };

    users.groups.${cfg.group} = { };

    # Enable WireGuard kernel module
    boot.kernelModules = [ "wireguard" ];

    # Required system packages
    environment.systemPackages = with pkgs; [
      wireguard-tools
      iproute2
    ];

    # Enable Caddy if requested
    services.caddy = mkIf cfg.caddy.enable {
      enable = true;
    };

    # Tunnel systemd service
    systemd.services.tunnel = {
      description = "tunnel - Tunneling made easy feat. WireGuard";
      after = [ "network.target" ] ++ optional cfg.caddy.enable "caddy.service";
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      environment = {
        TUNNEL_HOSTNAME = cfg.hostname;
        TUNNEL_CADDY_HOSTNAME = cfg.caddyHostname;
        TUNNEL_WG_INTERFACE_NAME = cfg.wireguardInterface;
        TUNNEL_WG_NETWORK = cfg.wireguardNetwork;
        TUNNEL_WG_PORT = toString cfg.wireguardPort;
        TUNNEL_STATIC_PATH = "${cfg.package}/share/tunnel/static";
      };
      
      path = with pkgs; [
        iproute2
        wireguard-tools
      ];

      serviceConfig = {
        Type = "simple";
        User = cfg.user;
        Group = cfg.group;
        Restart = "always";
        RestartSec = 10;

        # Security settings - relaxed for network management
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectSystem = "full"; # Changed from "strict" to allow access to /usr/bin
        ProtectHome = true;
        ProtectKernelTunables = false; # Need for WireGuard
        ProtectKernelModules = false; # Need for WireGuard
        ProtectControlGroups = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = false; # Disable to allow dynamic linking
        RestrictNamespaces = false; # Allow network namespaces

        # Network capabilities needed for WireGuard
        CapabilityBoundingSet = [
          "CAP_NET_ADMIN"
          "CAP_NET_RAW"
          "CAP_SYS_MODULE"
        ];
        AmbientCapabilities = [
          "CAP_NET_ADMIN"
          "CAP_NET_RAW"
          "CAP_SYS_MODULE"
        ];
      };

      # Ensure the service can bind to the port
      serviceConfig.ExecStart = lib.mkForce "${cfg.package}/bin/tunnel -addr 0.0.0.0:${toString cfg.listenPort}";
    };

    # Open firewall ports
    networking.firewall = {
      allowedTCPPorts = [
        cfg.listenPort
      ]
      ++ optional cfg.caddy.enable 80
      ++ optional cfg.caddy.enable 443;
      allowedUDPPorts = [ cfg.wireguardPort ];
    };

    # Ensure /etc/wireguard directory exists with correct permissions
    systemd.tmpfiles.rules = [
      "d /etc/wireguard 0700 ${cfg.user} ${cfg.group} -"
    ];
  };
}
