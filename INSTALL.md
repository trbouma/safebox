# Installation Instructions

## Python Poetry

These instructions are for Linux/Ubuntu

Make sure that you have the necessary dependencies installed. Open a terminal and run the following commands:
```
sudo apt update
sudo apt install python3-pip python3-venv curl

```

Install Poetry with the installation script
```
curl -sSL https://install.python-poetry.org | python3 -

```

Add Poetry to your path
```
export PATH="$HOME/.local/bin:$PATH"
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

```

Verify Installation
```
poetry --version
```
