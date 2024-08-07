# DNS Traffic Monitoring Tool

## Overview

This project is a DNS traffic monitoring tool written in Go. It captures and analyzes DNS traffic on a specified network interface, applying user-defined filters to store relevant domain information. Additionally, it functions as a DNS AXFR (zone transfer) server to retrieve captured domain names.

## Features

- **List Available Devices**: Lists all available network devices for packet capture.
- **Device Sniffing**: Captures DNS traffic on a specified device.
- **Filtering**: Filters stored domains based on user-defined criteria.
- **DNS AXFR Server**: Runs a DNS zone transfer server to retrieve captured domain names.

## Installation

1. **Clone the repository:**

   ```sh
   git clone https://github.com/skrashevich/go-ytds.git
   cd go-ytds
   ```

2. **Build the project:**

   ```sh
   go build -o ytds
   ```

3. **Install via `go install`:**

   ```sh
   go install github.com/skrashevich/go-ytds@latest
   ```

## Usage

### Command Line Flags

- `-list`: List all available devices.
- `-device <name>`: Specify the device to sniff on.
- `-dnsport <port>`: Specify the port for the DNS AXFR server (default: 5353).
- `-filter <domain>`: Filter stored domains (can be used multiple times).

### Examples

1. **List Available Devices:**

   ```sh
   ./dns-monitor -list
   ```

2. **Capture DNS Traffic on a Specific Device:**

   ```sh
   ./dns-monitor -device en0 -dnsport 5353 -filter googlevideo.com -filter youtube.com
   ```

3. **Get Captured Domain Names**

    ```sh
    % dig @127.0.0.1 -p 5353 googlevideo.com AXFR

    rr5.sn-q4fl6ns6.googlevideo.com. 3600 IN A 74.125.1.106
    ```

## Functionality

### Main Components

- **Packet Capture**: Uses `gopacket` and `pcap` to capture DNS traffic on the specified network device.
- **Filtering**: Filters captured DNS queries based on user-defined domain filters.
- **DNS AXFR Server**: Runs a DNS server that handles zone transfer requests, responding with stored DNS records.

## Contributing

1. **Fork the repository**
2. **Create a new branch**
3. **Make your changes**
4. **Submit a pull request**

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
