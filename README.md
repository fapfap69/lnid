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
06/12/2024 - ver. 2.0 - SSL support, organization, memory allocation check
                        Cmake installation

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- GETTING STARTED -->
## Getting Started

To start ...

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
5. On the LNID server you must run the service as deamon. This script works for a Linux distribution that uses **systemctl** program, with the exacutable in the **/usr/local/bin** directory
   ```sh
   ./installaIlServizio.sh
   ```
6. The client applications don't need installation

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


<p align="right">(<a href="#readme-top">back to top</a>)</p>


<!-- ROADMAP -->
## Roadmap

- [x] Istallation
- [x] SSL support
- [ ] Compilation option with the OSSL 3.0 support 
- [ ] Authentication
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
 