import { Injectable } from '@nestjs/common';

/**
 * Renders the install scripts (sh / ps1) the dashboard hands out as a single
 * command. The user runs:
 *
 *   curl -fsSL "{publicUrl}/v1/agents/install?token=…" | sudo sh
 *   iwr "{publicUrl}/v1/agents/install?token=…&platform=ps1" | iex
 *
 * The script downloads the per-tenant patched binary, registers it with the
 * OS service manager via `itom-agent install`, then starts it. Nothing is
 * left for the user to do.
 */
@Injectable()
export class InstallScriptService {
  renderShell(publicUrl: string, token: string): string {
    // Bash/sh — covers Linux + macOS.
    return `#!/bin/sh
# ITOM agent installer (Linux / macOS)
# This script is generated per-install with a short-lived token embedded.
set -e

SERVER_URL="${publicUrl}"
INSTALL_TOKEN="${token}"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$OS" in
  linux)  OS="linux" ;;
  darwin) OS="darwin" ;;
  *) echo "Unsupported OS: $OS" >&2; exit 1 ;;
esac

ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64)  ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

# kardianos/service installs as a system service — root is required.
if [ "$(id -u)" -ne 0 ]; then
  echo "This installer must be run as root (the agent registers as a system service)." >&2
  echo "Re-run with: curl -fsSL \\"$SERVER_URL/v1/agents/install?token=$INSTALL_TOKEN\\" | sudo sh" >&2
  exit 1
fi

INSTALL_DIR="/usr/local/bin"
DEST="$INSTALL_DIR/itom-agent"
BIN_URL="$SERVER_URL/v1/agents/build?token=$INSTALL_TOKEN&os=$OS&arch=$ARCH"

mkdir -p "$INSTALL_DIR"

echo "Detected: $OS/$ARCH"
echo "Downloading agent..."
curl -fsSL "$BIN_URL" -o "$DEST"
chmod +x "$DEST"

# macOS-specific post-install:
#   1. Strip the quarantine xattr (defensive — curl downloads usually don't
#      have it, but some sandboxed shells apply it).
#   2. Apply an ad-hoc code signature. On Apple Silicon (M-series), AMFI
#      kills unsigned arm64 binaries with SIGKILL ("Killed: 9") before they
#      ever run. Cross-compiled darwin binaries built on Linux/Windows have
#      no signature; ad-hoc signing locally fixes this without needing an
#      Apple Developer account. (For SaaS at scale, replace with a real
#      Developer ID signature + notarization at template-build time.)
if [ "$OS" = "darwin" ]; then
  xattr -d com.apple.quarantine "$DEST" 2>/dev/null || true
  if command -v codesign >/dev/null 2>&1; then
    if ! codesign --force --sign - "$DEST" 2>/dev/null; then
      echo "warn: ad-hoc codesign failed; the binary may be killed by macOS." >&2
      echo "      Install Xcode Command Line Tools (xcode-select --install) and rerun." >&2
    fi
  else
    echo "warn: 'codesign' not found. On Apple Silicon you must install Xcode Command Line Tools:" >&2
    echo "      xcode-select --install" >&2
    echo "      then rerun this installer." >&2
  fi
fi

echo "Registering service..."
"$DEST" install

echo "Starting service..."
"$DEST" start

echo
echo "ITOM agent installed and running as a system service."
echo "Logs: ~/.itom-agent/agent.log (and your system journal)"
echo "Manage with: itom-agent {status|stop|start|restart|uninstall}"
`;
  }

  renderPowerShell(publicUrl: string, token: string): string {
    // PowerShell — Windows. iwr | iex pipeline.
    return `# ITOM agent installer (Windows / PowerShell)
# This script is generated per-install with a short-lived token embedded.
$ErrorActionPreference = 'Stop'

$ServerUrl    = '${publicUrl}'
$InstallToken = '${token}'

# kardianos/service registers a Windows service via the SCM — admin is required.
$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Error "This installer must run in an elevated PowerShell. Right-click PowerShell -> Run as administrator and rerun."
  exit 1
}

$arch = if ([Environment]::Is64BitOperatingSystem) { 'amd64' } else { '386' }
if ($arch -ne 'amd64') {
  Write-Error "Unsupported architecture: $arch (only amd64 is supported on Windows)."
  exit 1
}

$InstallDir = "$env:ProgramFiles\\ITOM"
$Dest = Join-Path $InstallDir 'itom-agent.exe'
$BinUrl = "$ServerUrl/v1/agents/build?token=$InstallToken&os=windows&arch=$arch"

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

Write-Host "Detected: windows/$arch"
Write-Host "Downloading agent..."
Invoke-WebRequest -Uri $BinUrl -OutFile $Dest -UseBasicParsing

Write-Host "Registering service..."
& $Dest install

Write-Host "Starting service..."
& $Dest start

Write-Host ""
Write-Host "ITOM agent installed and running as a Windows service."
Write-Host "Logs: \$env:USERPROFILE\\.itom-agent\\agent.log (and the Windows event log)"
Write-Host "Manage with: itom-agent {status|stop|start|restart|uninstall}"
`;
  }
}
