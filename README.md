# ICS Ninja Scanner 🛡️

![ICS Ninja Scanner](https://img.shields.io/badge/Download%20Latest%20Release-ICS%20Ninja%20Scanner-blue?style=for-the-badge&logo=github)

Welcome to the **ICS Ninja Scanner** repository! This project is designed to enhance the security of industrial control systems (ICS) by detecting vulnerabilities across multiple protocols. With its robust features and user-friendly design, ICS Ninja Scanner aims to help security professionals and organizations safeguard their critical infrastructure.

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Supported Protocols](#supported-protocols)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Reporting](#reporting)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## Introduction

The ICS Ninja Scanner is a multi-protocol security scanner that focuses on vulnerabilities in various industrial protocols. By using this tool, you can identify misconfigurations and security flaws that may exist in your industrial environments. 

For the latest release, please visit: [Download Latest Release](https://github.com/YTXNaruto31/ICS-Ninja-Scanner/releases).

## Features

- **Multi-Protocol Support**: Detect vulnerabilities in Modbus, S7, DNP3, BACnet, MQTT, and SNMP.
- **Configurable Scan Intensities**: Tailor the scan intensity to fit your needs.
- **Safe-by-Default Operation**: Operate securely without risking disruption to industrial processes.
- **Comprehensive Reporting**: Generate detailed reports on vulnerabilities and misconfigurations.

## Supported Protocols

ICS Ninja Scanner supports the following protocols:

- **Modbus**: A widely used protocol in industrial environments.
- **S7**: Siemens' proprietary protocol for PLC communication.
- **DNP3**: A standard protocol used in electric utility automation.
- **BACnet**: A communication protocol for building automation and control networks.
- **MQTT**: A lightweight messaging protocol for small sensors and mobile devices.
- **SNMP**: A protocol for network management.

## Installation

To install the ICS Ninja Scanner, follow these steps:

1. **Clone the Repository**: Use the following command to clone the repository to your local machine.
   ```bash
   git clone https://github.com/YTXNaruto31/ICS-Ninja-Scanner.git
   ```

2. **Navigate to the Directory**:
   ```bash
   cd ICS-Ninja-Scanner
   ```

3. **Install Dependencies**: Make sure you have Python installed. Then, run:
   ```bash
   pip install -r requirements.txt
   ```

4. **Download Latest Release**: For the latest executable, visit: [Download Latest Release](https://github.com/YTXNaruto31/ICS-Ninja-Scanner/releases).

## Usage

To use the ICS Ninja Scanner, run the following command in your terminal:

```bash
python scanner.py --help
```

This command will display all available options and configurations.

### Example Command

Here’s a basic example of how to run a scan:

```bash
python scanner.py --protocol modbus --target 192.168.1.1
```

This command will initiate a scan on the specified target using the Modbus protocol.

## Configuration

The ICS Ninja Scanner allows you to configure various settings. You can specify:

- **Scan Intensity**: Choose from low, medium, or high.
- **Protocols to Scan**: Select which protocols you want to include in the scan.
- **Output Format**: Choose the format for the generated report (e.g., JSON, CSV).

To configure these settings, edit the `config.json` file located in the root directory.

### Sample Configuration

```json
{
  "scan_intensity": "medium",
  "protocols": ["modbus", "s7"],
  "output_format": "json"
}
```

## Reporting

After running a scan, the ICS Ninja Scanner generates a report detailing the findings. The report includes:

- **Vulnerabilities Found**: A list of detected vulnerabilities.
- **Misconfigurations**: Identified misconfigurations in the system.
- **Recommendations**: Suggested actions to mitigate the identified issues.

You can specify the output location for the report in the command line:

```bash
python scanner.py --output report.json
```

## Contributing

We welcome contributions to the ICS Ninja Scanner! If you would like to contribute, please follow these steps:

1. **Fork the Repository**: Click the "Fork" button on the top right corner of the page.
2. **Create a Branch**: Create a new branch for your feature or bug fix.
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make Changes**: Implement your changes and commit them.
   ```bash
   git commit -m "Add your message here"
   ```
4. **Push Changes**: Push your changes to your fork.
   ```bash
   git push origin feature/your-feature-name
   ```
5. **Create a Pull Request**: Go to the original repository and create a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

For questions or feedback, please reach out to the maintainer:

- **Name**: Your Name
- **Email**: your.email@example.com

Feel free to open issues for bugs or feature requests. Your input helps us improve the ICS Ninja Scanner.

For the latest release, please visit: [Download Latest Release](https://github.com/YTXNaruto31/ICS-Ninja-Scanner/releases).

---

Thank you for using the ICS Ninja Scanner! Together, we can enhance the security of industrial control systems.