#!/bin/bash

CONFIG_FILE="security_checks.conf"

echo "== Custom Security Checks =="

# Load the config file
if [[ ! -f $CONFIG_FILE ]]; then
    echo "[-] Configuration file $CONFIG_FILE not found!"
    exit 1
fi

# Read and run checks from config
index=1
while true; do
    description_var="Check${index}_Description"
    command_var="Check${index}_Command"

    # Read the variables from the file
    description=$(grep "^${description_var}=" "$CONFIG_FILE" | cut -d'=' -f2- | tr -d '"')
    command=$(grep "^${command_var}=" "$CONFIG_FILE" | cut -d'=' -f2- | tr -d '"')

    # Break the loop if no more checks
    if [[ -z $description || -z $command ]]; then
        break
    fi

    echo ""
    echo "[+] Check $index: $description"
    echo "---------------------------------"
    eval "$command"

    ((index++))
done