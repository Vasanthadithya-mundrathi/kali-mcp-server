#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';
import Docker from 'dockerode';

class KaliMCPServer {
  constructor() {
    this.server = new Server(
      {
        name: 'kali-mcp-server',
        version: '1.0.0',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.docker = new Docker();
    this.containerName = 'kali-mcp-container';

    this.setupToolHandlers();
    this.setupLifecycleHandlers();
  }

  setupToolHandlers() {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: [
          {
            name: 'run_kali_command',
            description: 'Execute a command inside the Kali Linux container',
            inputSchema: {
              type: 'object',
              properties: {
                command: {
                  type: 'string',
                  description: 'The command to execute in Kali container',
                },
                workdir: {
                  type: 'string',
                  description: 'Working directory for the command (optional)',
                  default: '/root',
                },
              },
              required: ['command'],
            },
          },
          {
            name: 'start_kali_container',
            description: 'Start the Kali Linux container if not running',
            inputSchema: {
              type: 'object',
              properties: {},
            },
          },
          {
            name: 'stop_kali_container',
            description: 'Stop the Kali Linux container',
            inputSchema: {
              type: 'object',
              properties: {},
            },
          },
          {
            name: 'kali_container_status',
            description: 'Check if Kali container is running',
            inputSchema: {
              type: 'object',
              properties: {},
            },
          },
          {
            name: 'install_kali_package',
            description: 'Install a package in Kali Linux using apt',
            inputSchema: {
              type: 'object',
              properties: {
                package: {
                  type: 'string',
                  description: 'Package name to install',
                },
              },
              required: ['package'],
            },
          },
          {
            name: 'update_kali_system',
            description: 'Update Kali Linux system packages',
            inputSchema: {
              type: 'object',
              properties: {},
            },
          },
          {
            name: 'kali_network_scan',
            description: 'Perform a network scan using Kali tools',
            inputSchema: {
              type: 'object',
              properties: {
                target: {
                  type: 'string',
                  description: 'Target IP or network to scan',
                },
                scan_type: {
                  type: 'string',
                  description: 'Type of scan (nmap, masscan, etc.)',
                  default: 'nmap',
                },
              },
              required: ['target'],
            },
          },
          {
            name: 'kali_service_scan',
            description: 'Scan for open services on target',
            inputSchema: {
              type: 'object',
              properties: {
                target: {
                  type: 'string',
                  description: 'Target IP to scan',
                },
              },
              required: ['target'],
            },
          },
          {
            name: 'kali_information_gathering',
            description: 'Gather information about target (whois, dns, etc.)',
            inputSchema: {
              type: 'object',
              properties: {
                target: {
                  type: 'string',
                  description: 'Target domain or IP',
                },
                tool: {
                  type: 'string',
                  description: 'Tool to use (whois, dnsrecon, theharvester, etc.)',
                  default: 'whois',
                },
              },
              required: ['target'],
            },
          },
          {
            name: 'kali_vulnerability_scan',
            description: 'Scan for vulnerabilities using Kali tools',
            inputSchema: {
              type: 'object',
              properties: {
                target: {
                  type: 'string',
                  description: 'Target URL or IP',
                },
                tool: {
                  type: 'string',
                  description: 'Tool to use (nikto, dirb, gobuster, etc.)',
                  default: 'nikto',
                },
              },
              required: ['target'],
            },
          },
          {
            name: 'kali_web_scan',
            description: 'Web application security scanning',
            inputSchema: {
              type: 'object',
              properties: {
                target: {
                  type: 'string',
                  description: 'Target URL',
                },
                tool: {
                  type: 'string',
                  description: 'Tool to use (sqlmap, dirb, nikto, etc.)',
                  default: 'sqlmap',
                },
                options: {
                  type: 'string',
                  description: 'Additional options for the tool',
                },
              },
              required: ['target'],
            },
          },
          {
            name: 'kali_password_crack',
            description: 'Password cracking tools',
            inputSchema: {
              type: 'object',
              properties: {
                tool: {
                  type: 'string',
                  description: 'Tool to use (john, hashcat, hydra)',
                  default: 'john',
                },
                file: {
                  type: 'string',
                  description: 'Input file (hashes, wordlist, etc.)',
                },
                options: {
                  type: 'string',
                  description: 'Additional options',
                },
              },
              required: ['tool'],
            },
          },
          {
            name: 'kali_wireless_tools',
            description: 'Wireless network analysis tools',
            inputSchema: {
              type: 'object',
              properties: {
                tool: {
                  type: 'string',
                  description: 'Tool to use (airodump-ng, aireplay-ng, etc.)',
                  default: 'airodump-ng',
                },
                interface: {
                  type: 'string',
                  description: 'Wireless interface to use',
                },
                options: {
                  type: 'string',
                  description: 'Additional options',
                },
              },
              required: ['tool'],
            },
          },
          {
            name: 'kali_forensics',
            description: 'Digital forensics tools',
            inputSchema: {
              type: 'object',
              properties: {
                tool: {
                  type: 'string',
                  description: 'Tool to use (volatility, autopsy, etc.)',
                  default: 'volatility',
                },
                file: {
                  type: 'string',
                  description: 'File to analyze',
                },
                options: {
                  type: 'string',
                  description: 'Additional options',
                },
              },
              required: ['tool'],
            },
          },
          {
            name: 'kali_ctf_tools',
            description: 'CTF-specific tools for capture the flag challenges',
            inputSchema: {
              type: 'object',
              properties: {
                tool: {
                  type: 'string',
                  description: 'CTF tool to use (steghide, binwalk, exiftool, strings, base64, etc.)',
                  default: 'strings',
                },
                file: {
                  type: 'string',
                  description: 'Input file to analyze',
                },
                options: {
                  type: 'string',
                  description: 'Additional options for the tool',
                },
              },
              required: ['tool'],
            },
          },
          {
            name: 'kali_reverse_engineering',
            description: 'Advanced reverse engineering and binary analysis tools',
            inputSchema: {
              type: 'object',
              properties: {
                tool: {
                  type: 'string',
                  description: 'RE tool to use (radare2, gdb, strace, ltrace, ROPgadget, etc.)',
                  default: 'radare2',
                },
                file: {
                  type: 'string',
                  description: 'Binary file to analyze',
                },
                options: {
                  type: 'string',
                  description: 'Additional options for the tool',
                },
              },
              required: ['tool'],
            },
          },
          {
            name: 'kali_crypto_tools',
            description: 'Cryptography and encoding tools',
            inputSchema: {
              type: 'object',
              properties: {
                tool: {
                  type: 'string',
                  description: 'Tool to use (openssl, base64, base32, xxd, etc.)',
                  default: 'openssl',
                },
                operation: {
                  type: 'string',
                  description: 'Operation to perform (encode, decode, encrypt, decrypt)',
                },
                input: {
                  type: 'string',
                  description: 'Input data or file',
                },
                options: {
                  type: 'string',
                  description: 'Additional options',
                },
              },
              required: ['tool'],
            },
          },
          {
            name: 'kali_network_exploitation',
            description: 'Network exploitation and post-exploitation tools',
            inputSchema: {
              type: 'object',
              properties: {
                tool: {
                  type: 'string',
                  description: 'Tool to use (nc, socat, scapy, chisel, etc.)',
                  default: 'nc',
                },
                target: {
                  type: 'string',
                  description: 'Target host:port',
                },
                options: {
                  type: 'string',
                  description: 'Additional options',
                },
              },
              required: ['tool'],
            },
          },
          {
            name: 'kali_web_exploitation',
            description: 'Web exploitation and analysis tools',
            inputSchema: {
              type: 'object',
              properties: {
                tool: {
                  type: 'string',
                  description: 'Tool to use (curl, wget, php, python3, etc.)',
                  default: 'curl',
                },
                target: {
                  type: 'string',
                  description: 'Target URL or host',
                },
                options: {
                  type: 'string',
                  description: 'Additional options',
                },
              },
              required: ['tool'],
            },
          },
          {
            name: 'kali_file_analysis',
            description: 'File analysis and extraction tools',
            inputSchema: {
              type: 'object',
              properties: {
                tool: {
                  type: 'string',
                  description: 'Tool to use (file, hexdump, xxd, od, etc.)',
                  default: 'file',
                },
                file: {
                  type: 'string',
                  description: 'File to analyze',
                },
                options: {
                  type: 'string',
                  description: 'Additional options',
                },
              },
              required: ['tool', 'file'],
            },
          },
          {
            name: 'kali_archive_tools',
            description: 'Archive and compression tools',
            inputSchema: {
              type: 'object',
              properties: {
                tool: {
                  type: 'string',
                  description: 'Tool to use (zip, unzip, tar, rar, etc.)',
                  default: 'tar',
                },
                operation: {
                  type: 'string',
                  description: 'Operation (extract, create, list)',
                },
                archive: {
                  type: 'string',
                  description: 'Archive file',
                },
                options: {
                  type: 'string',
                  description: 'Additional options',
                },
              },
              required: ['tool'],
            },
          },
          {
            name: 'kali_enumeration_tools',
            description: 'Enumeration and service detection tools',
            inputSchema: {
              type: 'object',
              properties: {
                tool: {
                  type: 'string',
                  description: 'Tool to use (enum4linux, smbclient, ftp, etc.)',
                  default: 'enum4linux',
                },
                target: {
                  type: 'string',
                  description: 'Target host or IP',
                },
                options: {
                  type: 'string',
                  description: 'Additional options',
                },
              },
              required: ['tool', 'target'],
            },
          },
          {
            name: 'kali_social_engineering',
            description: 'Social engineering tools',
            inputSchema: {
              type: 'object',
              properties: {
                tool: {
                  type: 'string',
                  description: 'Tool to use (setoolkit, king-phisher, etc.)',
                  default: 'setoolkit',
                },
                options: {
                  type: 'string',
                  description: 'Additional options',
                },
              },
              required: ['tool'],
            },
          },
          {
            name: 'kali_reverse_engineering',
            description: 'Reverse engineering tools',
            inputSchema: {
              type: 'object',
              properties: {
                tool: {
                  type: 'string',
                  description: 'Tool to use (gdb, radare2, ghidra, etc.)',
                  default: 'gdb',
                },
                file: {
                  type: 'string',
                  description: 'File to analyze',
                },
                options: {
                  type: 'string',
                  description: 'Additional options',
                },
              },
              required: ['tool'],
            },
          },
          {
            name: 'kali_stress_testing',
            description: 'Stress testing tools',
            inputSchema: {
              type: 'object',
              properties: {
                tool: {
                  type: 'string',
                  description: 'Tool to use (slowloris, torshammer, etc.)',
                  default: 'slowloris',
                },
                target: {
                  type: 'string',
                  description: 'Target URL or IP',
                },
                options: {
                  type: 'string',
                  description: 'Additional options',
                },
              },
              required: ['tool', 'target'],
            },
          },
          {
            name: 'kali_sniffing_spoofing',
            description: 'Network sniffing and spoofing tools',
            inputSchema: {
              type: 'object',
              properties: {
                tool: {
                  type: 'string',
                  description: 'Tool to use (wireshark, tcpdump, arpspoof, etc.)',
                  default: 'tcpdump',
                },
                interface: {
                  type: 'string',
                  description: 'Network interface',
                },
                options: {
                  type: 'string',
                  description: 'Additional options',
                },
              },
              required: ['tool'],
            },
          },
        ],
      };
    });

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      try {
        const { name, arguments: args } = request.params;

        switch (name) {
          case 'run_kali_command':
            return await this.runKaliCommand(args);
          case 'start_kali_container':
            return await this.startKaliContainer();
          case 'stop_kali_container':
            return await this.stopKaliContainer();
          case 'kali_container_status':
            return await this.kaliContainerStatus();
          case 'install_kali_package':
            return await this.installKaliPackage(args);
          case 'update_kali_system':
            return await this.updateKaliSystem();
          case 'kali_network_scan':
            return await this.kaliNetworkScan(args);
          case 'kali_service_scan':
            return await this.kaliServiceScan(args);
          case 'kali_information_gathering':
            return await this.kaliInformationGathering(args);
          case 'kali_vulnerability_scan':
            return await this.kaliVulnerabilityScan(args);
          case 'kali_web_scan':
            return await this.kaliWebScan(args);
          case 'kali_password_crack':
            return await this.kaliPasswordCrack(args);
          case 'kali_wireless_tools':
            return await this.kaliWirelessTools(args);
          case 'kali_forensics':
            return await this.kaliForensics(args);
          case 'kali_ctf_tools':
            return await this.kaliCTFTools(args);
          case 'kali_reverse_engineering':
            return await this.kaliReverseEngineering(args);
          case 'kali_crypto_tools':
            return await this.kaliCryptoTools(args);
          case 'kali_network_exploitation':
            return await this.kaliNetworkExploitation(args);
          case 'kali_web_exploitation':
            return await this.kaliWebExploitation(args);
          case 'kali_file_analysis':
            return await this.kaliFileAnalysis(args);
          case 'kali_archive_tools':
            return await this.kaliArchiveTools(args);
          case 'kali_enumeration_tools':
            return await this.kaliEnumerationTools(args);
          case 'kali_social_engineering':
            return await this.kaliSocialEngineering(args);
          case 'kali_reverse_engineering':
            return await this.kaliReverseEngineering(args);
          case 'kali_stress_testing':
            return await this.kaliStressTesting(args);
          case 'kali_sniffing_spoofing':
            return await this.kaliSniffingSpoofing(args);
          default:
            throw new McpError(
              ErrorCode.MethodNotFound,
              `Unknown tool: ${name}`
            );
        }
      } catch (error) {
        throw new McpError(
          ErrorCode.InternalError,
          `Tool execution failed: ${error.message}`
        );
      }
    });
  }

  setupLifecycleHandlers() {
    this.server.onerror = (error) => {
      console.error('Server error:', error);
    };

    process.on('SIGINT', async () => {
      await this.server.close();
      process.exit(0);
    });
  }

  async ensureContainerRunning() {
    const containers = await this.docker.listContainers({
      all: true,
      filters: { name: [this.containerName] },
    });

    if (containers.length === 0) {
      // Create and start container
      const container = await this.docker.createContainer({
        Image: 'kalilinux/kali-rolling',
        name: this.containerName,
        Tty: true,
        Cmd: ['/bin/bash'],
        HostConfig: {
          AutoRemove: false,
        },
      });

      await container.start();
      return container;
    } else {
      const container = this.docker.getContainer(containers[0].Id);

      if (containers[0].State !== 'running') {
        await container.start();
      }

      return container;
    }
  }

  async runKaliCommand(args) {
    const container = await this.ensureContainerRunning();
    const { command, workdir = '/root' } = args;

    const exec = await container.exec({
      Cmd: ['/bin/bash', '-c', `cd ${workdir} && ${command}`],
      AttachStdout: true,
      AttachStderr: true,
    });

    const stream = await exec.start({ hijack: true, stdin: false });

    return new Promise((resolve, reject) => {
      let output = '';
      let errorOutput = '';

      stream.on('data', (chunk) => {
        output += chunk.toString();
      });

      stream.on('error', (err) => {
        errorOutput += err.toString();
      });

      stream.on('end', () => {
        resolve({
          content: [
            {
              type: 'text',
              text: `Command executed successfully:\n\n${output}${errorOutput ? '\nErrors:\n' + errorOutput : ''}`,
            },
          ],
        });
      });
    });
  }

  async startKaliContainer() {
    const container = await this.ensureContainerRunning();
    const info = await container.inspect();

    return {
      content: [
        {
          type: 'text',
          text: `Kali container started successfully. Container ID: ${info.Id.substring(0, 12)}`,
        },
      ],
    };
  }

  async stopKaliContainer() {
    const containers = await this.docker.listContainers({
      filters: { name: [this.containerName] },
    });

    if (containers.length > 0) {
      const container = this.docker.getContainer(containers[0].Id);
      await container.stop();
    }

    return {
      content: [
        {
          type: 'text',
          text: 'Kali container stopped successfully.',
        },
      ],
    };
  }

  async kaliContainerStatus() {
    const containers = await this.docker.listContainers({
      all: true,
      filters: { name: [this.containerName] },
    });

    if (containers.length === 0) {
      return {
        content: [
          {
            type: 'text',
            text: 'Kali container does not exist. Use start_kali_container to create it.',
          },
        ],
      };
    }

    const container = containers[0];
    return {
      content: [
        {
          type: 'text',
          text: `Kali Container Status:
- Name: ${container.Names[0]}
- State: ${container.State}
- Status: ${container.Status}
- Image: ${container.Image}`,
        },
      ],
    };
  }

  async installKaliPackage(args) {
    const { package: packageName } = args;
    return await this.runKaliCommand({
      command: `apt update && apt install -y ${packageName}`,
    });
  }

  async updateKaliSystem() {
    return await this.runKaliCommand({
      command: 'apt update && apt upgrade -y',
    });
  }

  async kaliNetworkScan(args) {
    const { target, scan_type = 'nmap' } = args;

    let command;
    switch (scan_type) {
      case 'nmap':
        command = `nmap -sV -O ${target}`;
        break;
      case 'masscan':
        command = `masscan ${target} -p1-65535 --rate=1000`;
        break;
      default:
        command = `nmap ${target}`;
    }

    return await this.runKaliCommand({ command });
  }

  async kaliServiceScan(args) {
    const { target } = args;
    return await this.runKaliCommand({
      command: `nmap -sV -p- ${target}`,
    });
  }

  async kaliInformationGathering(args) {
    const { target, tool = 'whois' } = args;
    let command;

    switch (tool) {
      case 'whois':
        command = `whois ${target}`;
        break;
      case 'dnsrecon':
        command = `dnsrecon -d ${target}`;
        break;
      case 'theharvester':
        command = `theHarvester -d ${target} -l 500 -b google`;
        break;
      case 'dig':
        command = `dig ${target} ANY`;
        break;
      default:
        command = `${tool} ${target}`;
    }

    return await this.runKaliCommand({ command });
  }

  async kaliVulnerabilityScan(args) {
    const { target, tool = 'nikto' } = args;
    let command;

    switch (tool) {
      case 'nikto':
        command = `nikto -h ${target}`;
        break;
      case 'dirb':
        command = `dirb ${target}`;
        break;
      case 'gobuster':
        command = `gobuster dir -u ${target} -w /usr/share/wordlists/dirb/common.txt`;
        break;
      case 'dirbuster':
        command = `dirbuster ${target}`;
        break;
      default:
        command = `${tool} ${target}`;
    }

    return await this.runKaliCommand({ command });
  }

  async kaliWebScan(args) {
    const { target, tool = 'sqlmap', options = '' } = args;
    let command;

    switch (tool) {
      case 'sqlmap':
        command = `sqlmap -u "${target}" ${options}`;
        break;
      case 'dirb':
        command = `dirb ${target} ${options}`;
        break;
      case 'nikto':
        command = `nikto -h ${target} ${options}`;
        break;
      case 'wpscan':
        command = `wpscan --url ${target} ${options}`;
        break;
      default:
        command = `${tool} ${target} ${options}`;
    }

    return await this.runKaliCommand({ command });
  }

  async kaliPasswordCrack(args) {
    const { tool = 'john', file, options = '' } = args;
    let command;

    switch (tool) {
      case 'john':
        command = `john ${file} ${options}`;
        break;
      case 'hashcat':
        command = `hashcat -m 0 ${file} /usr/share/wordlists/rockyou.txt ${options}`;
        break;
      case 'hydra':
        command = `hydra ${options}`;
        break;
      default:
        command = `${tool} ${file} ${options}`;
    }

    return await this.runKaliCommand({ command });
  }

  async kaliWirelessTools(args) {
    const { tool = 'airodump-ng', networkInterface = 'wlan0', options = '' } = args;
    let command;

    switch (tool) {
      case 'airodump-ng':
        command = `airodump-ng ${networkInterface} ${options}`;
        break;
      case 'aireplay-ng':
        command = `aireplay-ng ${options} ${networkInterface}`;
        break;
      default:
        command = `${tool} ${options}`;
    }

    return await this.runKaliCommand({ command });
  }

  async kaliForensics(args) {
    const { tool = 'volatility', file, options = '' } = args;
    let command;

    switch (tool) {
      case 'volatility':
        command = `volatility -f ${file} ${options}`;
        break;
      case 'autopsy':
        command = `autopsy ${options}`;
        break;
      case 'binwalk':
        command = `binwalk ${file} ${options}`;
        break;
      default:
        command = `${tool} ${file} ${options}`;
    }

    return await this.runKaliCommand({ command });
  }

  async kaliExploitation(args) {
    const { tool = 'searchsploit', target, options = '' } = args;
    let command;

    switch (tool) {
      case 'searchsploit':
        command = `searchsploit ${target} ${options}`;
        break;
      case 'metasploit':
        command = `msfconsole -q -x "${options}"`;
        break;
      case 'armitage':
        command = `armitage ${options}`;
        break;
      default:
        command = `${tool} ${target} ${options}`;
    }

    return await this.runKaliCommand({ command });
  }

  async kaliSocialEngineering(args) {
    const { tool = 'setoolkit', options = '' } = args;
    let command;

    switch (tool) {
      case 'setoolkit':
        command = `setoolkit ${options}`;
        break;
      case 'king-phisher':
        command = `king-phisher ${options}`;
        break;
      default:
        command = `${tool} ${options}`;
    }

    return await this.runKaliCommand({ command });
  }

  async kaliReverseEngineering(args) {
    const { tool = 'gdb', file, options = '' } = args;
    let command;

    switch (tool) {
      case 'gdb':
        command = `gdb ${file} ${options}`;
        break;
      case 'radare2':
        command = `r2 ${file} ${options}`;
        break;
      case 'ghidra':
        command = `ghidra ${options}`;
        break;
      case 'objdump':
        command = `objdump -d ${file} ${options}`;
        break;
      default:
        command = `${tool} ${file} ${options}`;
    }

    return await this.runKaliCommand({ command });
  }

  async kaliStressTesting(args) {
    const { tool = 'slowloris', target, options = '' } = args;
    let command;

    switch (tool) {
      case 'slowloris':
        command = `slowloris ${target} ${options}`;
        break;
      case 'torshammer':
        command = `torshammer --target ${target} ${options}`;
        break;
      case 'pyddos':
        command = `pyddos ${target} ${options}`;
        break;
      default:
        command = `${tool} ${target} ${options}`;
    }

    return await this.runKaliCommand({ command });
  }

  async kaliSniffingSpoofing(args) {
    const { tool = 'tcpdump', networkInterface = 'eth0', options = '' } = args;
    let command;

    switch (tool) {
      case 'tcpdump':
        command = `tcpdump -i ${networkInterface} ${options}`;
        break;
      case 'wireshark':
        command = `wireshark ${options}`;
        break;
      case 'arpspoof':
        command = `arpspoof ${options}`;
        break;
      case 'dsniff':
        command = `dsniff ${options}`;
        break;
      default:
        command = `${tool} -i ${networkInterface} ${options}`;
    }

    return await this.runKaliCommand({ command });
  }

  async kaliCTFTools(args) {
    const { tool = 'strings', file, options = '' } = args;
    let command;

    switch (tool) {
      case 'steghide':
        command = `steghide ${options}`;
        break;
      case 'binwalk':
        command = `binwalk ${file} ${options}`;
        break;
      case 'exiftool':
        command = `exiftool ${file} ${options}`;
        break;
      case 'strings':
        command = `strings ${file} ${options}`;
        break;
      case ' foremost':
        command = `foremost ${file} ${options}`;
        break;
      default:
        command = `${tool} ${file} ${options}`;
    }

    return await this.runKaliCommand({ command });
  }

  async kaliReverseEngineering(args) {
    const { tool = 'radare2', file, options = '' } = args;
    let command;

    switch (tool) {
      case 'radare2':
      case 'r2':
        command = `radare2 -A ${file} ${options}`;
        break;
      case 'gdb':
        command = `gdb ${file} ${options}`;
        break;
      case 'strace':
        command = `strace ${file} ${options}`;
        break;
      case 'ltrace':
        command = `ltrace ${file} ${options}`;
        break;
      case 'ROPgadget':
        command = `ROPgadget --binary ${file} ${options}`;
        break;
      case 'checksec':
        command = `checksec ${file} ${options}`;
        break;
      case 'patchelf':
        command = `patchelf ${options} ${file}`;
        break;
      case 'objdump':
        command = `objdump -d ${file} ${options}`;
        break;
      case 'readelf':
        command = `readelf -a ${file} ${options}`;
        break;
      case 'nm':
        command = `nm ${file} ${options}`;
        break;
      case 'ldd':
        command = `ldd ${file} ${options}`;
        break;
      case 'file':
        command = `file ${file} ${options}`;
        break;
      default:
        command = `${tool} ${file} ${options}`;
    }

    return await this.runKaliCommand({ command });
  }

  async kaliCryptoTools(args) {
    const { tool = 'openssl', operation = 'enc', input, options = '' } = args;
    let command;

    switch (tool) {
      case 'openssl':
        command = `openssl ${operation} ${options}`;
        break;
      case 'base64':
        command = `base64 ${operation} ${options}`;
        break;
      case 'base32':
        command = `base32 ${operation} ${options}`;
        break;
      case 'xxd':
        command = `xxd ${options}`;
        break;
      case 'hexdump':
        command = `hexdump ${options}`;
        break;
      default:
        command = `${tool} ${options}`;
    }

    return await this.runKaliCommand({ command });
  }

  async kaliNetworkExploitation(args) {
    const { tool = 'nc', target, options = '' } = args;
    let command;

    switch (tool) {
      case 'nc':
      case 'netcat':
        command = `nc ${target} ${options}`;
        break;
      case 'socat':
        command = `socat ${options}`;
        break;
      case 'scapy':
        command = `python3 -c "import scapy; ${options}"`;
        break;
      case 'chisel':
        command = `chisel ${options}`;
        break;
      default:
        command = `${tool} ${target} ${options}`;
    }

    return await this.runKaliCommand({ command });
  }

  async kaliWebExploitation(args) {
    const { tool = 'curl', target, options = '' } = args;
    let command;

    switch (tool) {
      case 'curl':
        command = `curl ${target} ${options}`;
        break;
      case 'wget':
        command = `wget ${target} ${options}`;
        break;
      case 'php':
        command = `php ${options}`;
        break;
      case 'python3':
        command = `python3 ${options}`;
        break;
      case 'ruby':
        command = `ruby ${options}`;
        break;
      default:
        command = `${tool} ${target} ${options}`;
    }

    return await this.runKaliCommand({ command });
  }

  async kaliFileAnalysis(args) {
    const { tool = 'file', file, options = '' } = args;
    let command;

    switch (tool) {
      case 'file':
        command = `file ${file} ${options}`;
        break;
      case 'hexdump':
        command = `hexdump ${file} ${options}`;
        break;
      case 'xxd':
        command = `xxd ${file} ${options}`;
        break;
      case 'od':
        command = `od ${file} ${options}`;
        break;
      case 'stat':
        command = `stat ${file} ${options}`;
        break;
      default:
        command = `${tool} ${file} ${options}`;
    }

    return await this.runKaliCommand({ command });
  }

  async kaliArchiveTools(args) {
    const { tool = 'tar', operation = 'tf', archive, options = '' } = args;
    let command;

    switch (tool) {
      case 'tar':
        command = `tar ${operation} ${archive} ${options}`;
        break;
      case 'zip':
        command = `zip ${options}`;
        break;
      case 'unzip':
        command = `unzip ${options}`;
        break;
      case 'rar':
        command = `rar ${operation} ${archive} ${options}`;
        break;
      case 'unrar':
        command = `unrar ${operation} ${archive} ${options}`;
        break;
      default:
        command = `${tool} ${options}`;
    }

    return await this.runKaliCommand({ command });
  }

  async kaliEnumerationTools(args) {
    const { tool = 'enum4linux', target, options = '' } = args;
    let command;

    switch (tool) {
      case 'enum4linux':
        command = `enum4linux ${target} ${options}`;
        break;
      case 'smbclient':
        command = `smbclient ${options}`;
        break;
      case 'ftp':
        command = `ftp ${target} ${options}`;
        break;
      case 'telnet':
        command = `telnet ${target} ${options}`;
        break;
      case 'ssh':
        command = `ssh ${options}`;
        break;
      default:
        command = `${tool} ${target} ${options}`;
    }

    return await this.runKaliCommand({ command });
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.log('Kali MCP Server running on stdio');
  }
}

// Start the server
const server = new KaliMCPServer();
server.run().catch(console.error);