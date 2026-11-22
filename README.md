## openvpn-install
OpenVPN [road warrior](http://en.wikipedia.org/wiki/Road_warrior_%28computing%29) installer for Ubuntu, Debian, AlmaLinux, Rocky Linux, CentOS and Fedora.

This project is a fork of [Nyr/openvpn-install](https://github.com/Nyr/openvpn-install), with modifications including security hardening, split tunnelling, and client management. It is distributed under the [MIT License](LICENSE.txt); the original copyright and license are retained.

This script will let you set up your own VPN server in no more than a minute, even if you haven't used OpenVPN before. It has been designed to be as unobtrusive and universal as possible.

### Installation
Run the script and follow the assistant:

```plain text
wget https://ben1one.github.io/openvpn-install/openvpn-install.sh -O openvpn-install.sh && bash openvpn-install.sh
```

Once it ends, you can run it again to add more users, remove some of them or even completely uninstall OpenVPN.

For new installations, the server and generated client profiles require TLS 1.2 or newer and negotiate AES-256-GCM or AES-128-GCM. Client software must support OpenVPN 2.5 or newer and a matching cipher. During installation and when adding a client, you can choose to protect that client's private key with a passphrase; the client will need it when connecting. Keep all client profiles private, even when their keys are encrypted.

New installations also use a systemd service sandbox. Its writable lease database is stored in `/var/lib/openvpn-install`, and is removed when uninstalling. Existing installations are not automatically reconfigured; newly added clients continue to use their existing server's client template.

During a new installation, choose full-tunnel routing or split tunnelling with one or more IPv4 network addresses in CIDR notation (for example, `192.168.10.0/24`). In split mode, only those routes and the VPN's own subnet are added; other traffic follows the client's existing routes. IPv6 routes are not pushed in split mode. DNS settings are still pushed and client behavior depends on its OpenVPN software. The VPN server and any destination networks must have suitable forwarding and return routes. Existing installations retain their routing configuration.

The management menu can list clients and certificate expiry dates, show connected clients, export an existing client profile to a chosen existing directory, and display a profile as a QR code when `qrencode` is installed. Profiles contain private keys: transfer them securely. Some profiles exceed the QR format's capacity; export the file instead. Connection status requires an OpenVPN `status` directive; new installations configure it automatically. Existing installations without status logging need it configured separately.

### Security checks

Run `bash tests/test-security.sh` with Docker running and internet access available. It checks the installer syntax, verifies the generated systemd drop-in against Ubuntu 22.04's OpenVPN service, checks cipher support and split-route validation, and exercises the client passphrase prompt using a mock Easy-RSA command. The disposable container installs packages and is removed after the test.

These checks do not start systemd or OpenVPN, create a real encrypted key, or test VPN traffic. Validate those separately on a Linux test machine or VM before deployment.
