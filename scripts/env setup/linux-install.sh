#!/bin/bash
set -e

# Install dependencies
sudo apt update
sudo apt install -y build-essential zlib1g-dev libssl-dev \
  libncurses5-dev libbz2-dev libreadline-dev libsqlite3-dev \
  wget curl llvm libncursesw5-dev xz-utils tk-dev libxml2-dev \
  libxmlsec1-dev libffi-dev liblzma-dev python3-setuptools

# Install Python 3.11
PYTHON_VERSION=3.11.8
cd /tmp
wget https://www.python.org/ftp/python/$PYTHON_VERSION/Python-$PYTHON_VERSION.tgz
tar -xf Python-$PYTHON_VERSION.tgz
cd Python-$PYTHON_VERSION
./configure --enable-optimizations
make -j$(nproc)
sudo make altinstall  # prevents overwriting system python

# Verify installation
python3.11 --version

# Install Poetry
curl -sSL https://install.python-poetry.org | python3.11 -

# Add Poetry to PATH
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

echo -e "\n🎉 Python 3.11 and Poetry installed successfully."
