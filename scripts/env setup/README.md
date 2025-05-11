# Environment Setup Scripts

This directory contains scripts for setting up the development environment for the AD Protect Agent on different operating systems.

## Available Scripts

### Windows Installation Script (`win-install.ps1`)

This PowerShell script automates the setup process for Windows environments by:
- Installing Python 3.11 from the official Python website
- Installing Poetry (Python dependency management tool)
- Configuring the system PATH to include Poetry

### macOS Installation Script (`mac-install.sh`)

This Bash script automates the setup process for macOS environments by:
- Checking for and requiring Homebrew package manager
- Installing Python 3.11 via Homebrew
- Installing Poetry (Python dependency management tool)
- Configuring the shell environment to include Poetry in PATH

### Linux Installation Script (`linux-install.sh`)

This Bash script automates the setup process for Linux environments (primarily Debian/Ubuntu-based) by:
- Installing required system dependencies
- Downloading and compiling Python 3.11 from source
- Installing Poetry (Python dependency management tool)
- Configuring the shell environment to include Poetry in PATH

## Usage

### Windows
```powershell
.\win-install.ps1
```

### macOS
```bash
chmod +x mac-install.sh
./mac-install.sh
```

### Linux
```bash
chmod +x linux-install.sh
./linux-install.sh
```

After running the appropriate script for your platform, you'll have a properly configured environment with Python 3.11 and Poetry ready for developing and running the AD Protect Agent.
