# Kali MCP Server 🌟

A powerful MCP (Model Context Protocol) server that provides access to Kali Linux penetration testing tools through Docker containers.

## Features

- 🚀 **20 Specialized Tools** for comprehensive Kali Linux operations
- 🐳 **Docker Integration** - Runs Kali in isolated containers
- 🔒 **Secure Execution** - Commands run inside Kali container
- 📦 **Easy Installation** - Available globally via npm
- 🛠️ **Complete Toolkit** - All major Kali Linux tool categories

## Installation

### Global Installation (Recommended)
```bash
npm install -g kali-mcp-server
```

### Local Installation
```bash
git clone <repository-url>
cd kali-mcp-server
npm install
npm start
```

## MCP Configuration

Add this to your `.kilocode/mcp.json` or any MCP configuration:

```json
{
  "mcpServers": {
    "kali": {
      "command": "npx",
      "args": ["-y", "kali-mcp-server"]
    }
  }
}
```

## Available Tools (20 Total!)

### Core Container Management
1. **`run_kali_command`** - Execute any command inside Kali container
2. **`start_kali_container`** - Start the Kali container
3. **`stop_kali_container`** - Stop the Kali container
4. **`kali_container_status`** - Check container status

### Package Management
5. **`install_kali_package`** - Install Kali packages via apt
6. **`update_kali_system`** - Update Kali system packages

### Network & Service Scanning
7. **`kali_network_scan`** - Network scanning (nmap, masscan)
8. **`kali_service_scan`** - Service scanning and enumeration

### Information Gathering
9. **`kali_information_gathering`** - OSINT and reconnaissance (whois, dnsrecon, theharvester)

### Vulnerability Assessment
10. **`kali_vulnerability_scan`** - Vulnerability scanning (nikto, dirb, gobuster)

### Web Application Security
11. **`kali_web_scan`** - Web app testing (sqlmap, dirb, nikto, wpscan)

### Password Cracking
12. **`kali_password_crack`** - Password tools (john, hashcat, hydra)

### Wireless Tools
13. **`kali_wireless_tools`** - WiFi analysis (airodump-ng, aireplay-ng)

### Digital Forensics
14. **`kali_forensics`** - Forensics tools (volatility, autopsy, binwalk)

### Exploitation Tools
15. **`kali_exploitation`** - Exploit development (metasploit, searchsploit)

### Social Engineering
16. **`kali_social_engineering`** - SE tools (setoolkit, king-phisher)

### Reverse Engineering
17. **`kali_reverse_engineering`** - Advanced RE tools (radare2, gdb, strace, ltrace, checksec, patchelf)

### Stress Testing
18. **`kali_stress_testing`** - DoS tools (slowloris, torshammer)

### Network Sniffing & Spoofing
19. **`kali_sniffing_spoofing`** - Sniffing tools (wireshark, tcpdump, arpspoof)

### Universal Command Tool
20. **`run_kali_command`** - Execute any Kali command directly

## Use Cases

- **Penetration Testing** - Complete toolkit in isolated environment
- **Network Security** - Scanning, sniffing, and spoofing tools
- **Web Application Security** - SQL injection, directory scanning, vulnerability assessment
- **Wireless Security** - WiFi analysis and attack tools
- **Digital Forensics** - Memory analysis, disk forensics, evidence collection
- **Password Security** - Hash cracking, brute force testing
- **Reverse Engineering** - Binary analysis, debugging, disassembly, decompilation
- **Social Engineering** - Phishing, credential harvesting tools
- **Vulnerability Research** - Exploit development and testing
- **Security Training** - Learn ethical hacking in safe environment
- **CTF Challenges** - Complete toolkit for capture the flag competitions

## Security Features

- 🔐 Commands execute inside Docker container
- 🛡️ Isolated from host system
- 📝 Full audit trail of executed commands
- 🗑️ Automatic cleanup of containers

## Requirements

- Docker installed and running
- Node.js 16+
- Internet connection (for npm packages)

## Development

```bash
# Clone and setup
git clone <repository-url>
cd kali-mcp-server
npm install

# Run locally
npm start

# Publish to npm (after npm login)
npm publish --access public
```

## License

MIT License - See LICENSE file for details.

## Support

For issues and feature requests, please create an issue in the repository.

---

**⚠️ Disclaimer:** This tool is for educational and authorized penetration testing only. Ensure you have permission before scanning any networks or systems.