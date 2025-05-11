#!/bin/bash
set -e

# Ensure Homebrew is installed
if ! command -v brew &>/dev/null; then
  echo "🚨 Homebrew not found. Install it first: https://brew.sh/"
  exit 1
fi

# Install Python 3.11
brew install python@3.11

# Symlink python3.11 to /usr/local/bin if needed
brew link --overwrite python@3.11

# Install Poetry
curl -sSL https://install.python-poetry.org | python3.11 -

# Add Poetry to PATH
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc

echo -e "\n🎉 Python 3.11 and Poetry installed successfully."
