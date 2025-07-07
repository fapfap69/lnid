<!-- PROJECT SHIELDS -->
<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->
[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]

<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#configuration">Configuration</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgments">Acknowledgments</a></li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## About The Project

The LNID - Local Network Identity Discovery project try to solve the issue of discover the IP address of a machine that runs on a LAN and uses the DHCP services.

User case : assume that on a department LAN there are one or more machines/devices connected, that are configured by the DHCP protocol. Then we need remotely access to those devices (eg. ssh session). We don't known the IP address and the machine hostname isn't registered to the DNS server.

LNID solution:
* A very light service, running in background, listen on a dedicated port is able to replay the request with the defined HOSTNAME
* A client program executes a scan of all subnet LAN IP addresses in order to discover a running LNID server that replay with its hostname.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### Built With

Only basic C POSIX functionalities: portability, lightness, semplicity.

OSSL v3.0 nedded !

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### History

28/11/2024 - First release v.1.0

28/11/2024 - Add the MAC address reference v.1.1

06/12/2024 - ver. 2.0 - SSL support, organization, memory allocation check, Cmake installation

06/07/2025 - ver. 2.1 - Improve security 


<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- GETTING STARTED -->
## Getting Started

LNID => **L**ast **N**ight **I** **D**reamed... :)

### Prerequisites

Any Linux/MacOS systems with a C compiler - C+11 minimum. Nathing prevent the compilation under Windows (no tested) 

### Installation

In order to install LNID

1. Clone the repo 
   ```sh
   git clone https://github.com/fapfap69/lnid.git
   ```
2. make the CMakeLists.txt

   ```sh
   cd src
   mkdir build
   cd build
   cmake ..
   ```
3. make tke executables
   ```sh
   make all
   ```
4. Copy executable files in the **/usr/local/bin/** folder. In order to do this you need the powers of Super Cow, otherwise you can put the for executables where you have the right rights
   ```sh
   make install
   ```
5. On the LNID server you must run the service as daemon. This script works for a Linux distribution that uses **systemctl** program, with the executable in the **/usr/local/bin** directory
   ```sh
   sudo ./install-server.sh
   ```
6. The client applications don't need installation

7. For automatic hostname resolution, install the resolver daemon:
   ```sh
   sudo ./install-resolver.sh
   ```
   This enables transparent access to LNID servers by hostname (e.g., `ssh myserver` instead of `ssh 192.168.1.100`)

<p align="right">(<a href="#readme-top">back to top</a>)</p>


<!-- USAGE EXAMPLES -->
## Usage

**lnid-cli** The test client, used to  verify that the service is running on the LNID server.
   ```sh
    ./lnid-cli -i \<indirizzo_ip\> -p \<porta\> -d -v -h
   ```
the IP address is mandatory, the port number not.

**lnid-scan** Runs a scan for all the IP addresses of the subnet and return all the active LNID servers.
   ```sh
    ./lnid-scan -s \<indirizzo_subnet\> -p \<porta\>  -t \<milliseconds\> -o \<milliseconds\> -d -v -h
   ```
the IP address for the subnet is mandatory, example: **192.168.1**

**lnid-search** Runs a scan for all the IP addresses of the subnet and return the IP of the searched hostname.
   ```sh
    ./lnid-search -n \<nome_host\> -s \<indirizzo_subnet\> -p \<porta\>  -t \<milliseconds\> -o \<milliseconds\> -v -h
   ```
the IP address for the subnet is mandatory, example: **192.168.1**

**lnid-resolver** Automatic daemon that maintains /etc/hosts updated with discovered LNID servers.
   ```sh
    sudo ./lnid-resolver -s \<subnet\> -i \<interval\> -p \<porta\> -f -c -v -h
   ```
Runs as system daemon, automatically discovers hosts and updates /etc/hosts for transparent access.

**lnid-hosts** Management tool for LNID entries in /etc/hosts.
   ```sh
    ./lnid-hosts <list|clean|backup|status>
   ```
Manages LNID-discovered entries in the hosts file.


<p align="right">(<a href="#readme-top">back to top</a>)</p>


<!-- CONFIGURATION -->
## Configuration

LNID provides flexible configuration options for both server and resolver components through configuration files and command-line parameters.

### Server Configuration

The LNID server can be configured via `/etc/lnid-server.conf` file:

```bash
# LNID Server Configuration
# Network interface to use
ETHERNET=eth0

# UDP listening port
PORT=16969

# Enable encrypted communication (0=no, 1=yes)
ENCRYPTED=0

# Enable secure mode - access control (0=no, 1=yes)
SECURE_MODE=1

# Enable verbose logging (0=no, 1=yes)
VERBOSE=0
```

**Server Management:**
```sh
# View current configuration
lnid-server config

# Test server functionality
lnid-server test

# Control server service
sudo lnid-server start|stop|restart

# View server status
lnid-server status
```

### Resolver Configuration

The LNID resolver daemon can be configured via `/etc/lnid-resolver.conf` file:

```bash
# LNID Resolver Configuration
# Subnet to scan (without .0 suffix)
SUBNET=192.168.1

# Scan interval in seconds (minimum 60)
SCAN_INTERVAL=300

# LNID server port
PORT=16969

# Enable encrypted communication (0=no, 1=yes)
ENCRYPTED=0

# Enable verbose logging (0=no, 1=yes)
VERBOSE=0
```

**Resolver Management:**
```sh
# View discovered hosts
lnid-hosts list

# View resolver status
lnid-hosts status

# Clean LNID entries from /etc/hosts
sudo lnid-hosts clean

# Backup /etc/hosts
sudo lnid-hosts backup
```

### Configuration Examples

**Example 1: Basic LAN Setup**
```bash
# Server on 192.168.1.100
ETHERNET=eth0
PORT=16969
SECURE_MODE=1

# Resolver scanning 192.168.1.x network
SUBNET=192.168.1
SCAN_INTERVAL=300
```

**Example 2: Secure Multi-Network Setup**
```bash
# Server with encryption enabled
ETHERNET=eth0
PORT=16969
ENCRYPTED=1
SECURE_MODE=1
VERBOSE=1

# Resolver with encryption and frequent scans
SUBNET=10.0.1
SCAN_INTERVAL=120
ENCRYPTED=1
VERBOSE=1
```

**Example 3: Development Environment**
```bash
# Server in debug mode
ETHERNET=lo
PORT=17000
SECURE_MODE=0
VERBOSE=1

# Resolver for testing
SUBNET=127.0.0
SCAN_INTERVAL=60
VERBOSE=1
```

### Configuration Priority

1. **Command-line parameters** (highest priority)
2. **Configuration files** (`/etc/lnid-*.conf`)
3. **Default values** (lowest priority)

### Network Security

When `SECURE_MODE=1` (default), the server restricts sensitive information access to:
- Localhost (127.0.0.0/8)
- Private networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)

Public IP addresses receive limited information for security.

<p align="right">(<a href="#readme-top">back to top</a>)</p>


<!-- ROADMAP -->
## Roadmap

- [x] Istallation
- [x] SSL support
- [x] Compilation option with the OSSL 3.0 support 
- [x] Authentication
- [ ] Extend to Windows platform
- [ ] Translation in english
- [ ] Fix

<p align="right">(<a href="#readme-top">back to top</a>)</p>


<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".
Don't forget to give the project a star! Thanks again!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Top contributors:

<a href="https://github.com/fapfap69/lnid/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=fapfap69/lnid" alt="contrib.rocks image" />
</a>

<p align="right">(<a href="#readme-top">back to top</a>)</p>


<!-- LICENSE -->
## License

Distributed under the Creative Common 4.0. See `LICENSE.txt` for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>


<!-- CONTACT -->
## Contact

Antonio Franco - franco.antonio63@gmail.com

Project Link: [https://github.com/fapfap69/lnid](https://github.com/fapfap69/lnid)

<p align="right">(<a href="#readme-top">back to top</a>)</p>


<!-- ACKNOWLEDGMENTS -->
## Acknowledgments

Use this space to list resources you find helpful and would like to give credit to. I've included a few of my favorites to kick things off!

* [Choose an Open Source License](https://choosealicense.com)
* [GitHub Pages](https://pages.github.com)

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/fapfap69/lnid.svg?style=for-the-badge
[contributors-url]: https://github.com/fapfap69/lnid/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/fapfap69/lnid.svg?style=for-the-badge
[forks-url]: https://github.com/fapfap69/lnid/network/members
[stars-shield]: https://img.shields.io/github/stars/fapfap69/lnid.svg?style=for-the-badge
[stars-url]: https://github.com/fapfap69/lnid/stargazers
[issues-shield]: https://img.shields.io/github/issues/fapfap69/lnid.svg?style=for-the-badge
[issues-url]: https://github.com/fapfap69/lnid/issues
[license-shield]: https://img.shields.io/github/license/fapfap69/lnid.svg?style=for-the-badge
[license-url]: https://github.com/fapfap69/lnid/blob/master/LICENSE.txt
 