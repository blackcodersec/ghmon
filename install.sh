#!/bin/bash
# Installation script for ghmon-cli

# --- Helper Functions ---
is_command() {
    command -v "$1" >/dev/null 2>&1
}

is_screen_installed() {
    is_command screen
}

install_screen_apt() {
    echo "Attempting to install screen using apt (Debian/Ubuntu)..."
    if [ "$(id -u)" -ne 0 ]; then
        sudo apt-get update && sudo apt-get install -y screen
    else
        apt-get update && apt-get install -y screen
    fi
    return $?
}

install_screen_dnf() {
    echo "Attempting to install screen using dnf (Fedora)..."
    if [ "$(id -u)" -ne 0 ]; then
        sudo dnf install -y screen
    else
        dnf install -y screen
    fi
    return $?
}

install_screen_brew() {
    echo "Attempting to install screen using brew (macOS)..."
    brew install screen
    return $?
}

print_manual_install_instructions() {
    echo "---------------------------------------------------------------------"
    echo "Failed to automatically install 'screen'."
    echo "Please install 'screen' manually to ensure continuous operation."
    echo "Refer to the README.md for manual installation instructions."
    echo "---------------------------------------------------------------------"
}

# --- Main Script ---

# Check if Python 3.8+ is installed
python3 --version >/dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Error: Python 3.8+ is required but not found."
    echo "Please install Python 3.8 or higher before continuing."
    exit 1
fi

# Check if git is installed
git --version >/dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Error: Git is required but not found."
    echo "Please install Git before continuing."
    exit 1
fi

# Check and install screen
if is_screen_installed; then
    echo "Screen is already installed."
else
    echo "Screen is not installed. It's recommended for continuous operation."
    INSTALL_SUCCESS=false
    if is_command apt-get; then
        install_screen_apt && INSTALL_SUCCESS=true
    elif is_command dnf; then
        install_screen_dnf && INSTALL_SUCCESS=true
    elif is_command brew; then
        install_screen_brew && INSTALL_SUCCESS=true
    else
        echo "No known package manager (apt, dnf, brew) found."
    fi

    if [ "$INSTALL_SUCCESS" = true ]; then
        if is_screen_installed; then
            echo "Screen installed successfully."
        else
            # This case might happen if installation command ran but screen is still not found
            echo "Screen installation command was executed, but 'screen' command is still not found."
            print_manual_install_instructions
        fi
    else
        print_manual_install_instructions
    fi
fi


# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
# Note: Activation is for the current script session.
# The user will need to activate it manually in their shell.
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install pyyaml click requests pygithub python-gitlab python-telegram-bot discord.py colorama

# Install the package in development mode
echo "Installing ghmon-cli..."
pip install -e .


echo "Installation completed successfully!"
echo "Remember to activate the virtual environment in your shell: source venv/bin/activate"
