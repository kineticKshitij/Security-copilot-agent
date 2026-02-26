#!/bin/bash
# Auto-generated security remediation script
# Finding ID: finding-20250806-101751
# Finding Type: OPEN_TO_INTERNET
# Severity: HIGH
# Generated: 2025-08-06T10:18:00.813253

set -e

echo "Applying security fix for finding: finding-20250806-101751"
echo "Affected resource: SSH"
echo "Resource group: Honeypot_group"

# Fix for NSG rule 'SSH' - Restrict source to specific networks
# Replace 'YOUR_MANAGEMENT_NETWORK' with your actual management network CIDR

az network nsg rule update \
  --resource-group "Honeypot_group" \
  --nsg-name "$(echo '/subscriptions/e17f4f74-0d91-4313-9716-0a2edcceefb7/resourceGroups/Honeypot_group/providers/Microsoft.Network/networkSecurityGroups/Honeypot-nsg/securityRules/SSH' | cut -d'/' -f9)" \
  --name "SSH" \
  --source-address-prefix "YOUR_MANAGEMENT_NETWORK" \
  --description "Restricted access - Updated by Security Copilot"


echo "Security fix applied successfully!"
