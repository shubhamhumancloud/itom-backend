$go = "C:\Program Files\Go\bin\go.exe"
$binary = "itom-agent"
$version = if ($env:VERSION) { $env:VERSION } else { "0.2.0" }
$ldflags = "-s -w -X main.Version=$version"
$dist = "dist"
# BE serves binaries and install.sh from this folder
$beDist = "..\BE\agents-dist"

$target = if ($args[0]) { $args[0] } else { "build" }

function Run-Tidy {
    Write-Host "Running go mod tidy..."
    & $go mod tidy
    if (-not $?) { exit 1 }
}

function Run-Build {
    Run-Tidy
    New-Item -ItemType Directory -Force $dist | Out-Null
    Write-Host "Building for current platform..."
    & $go build -ldflags $ldflags -o "$dist/$binary.exe" ./cmd/agentd
    if ($?) { Write-Host "Done: $dist/$binary.exe" }
}

function Run-BuildAll {
    Run-Tidy
    New-Item -ItemType Directory -Force $dist | Out-Null
    New-Item -ItemType Directory -Force $beDist | Out-Null

    $platforms = @(
        @{ OS="linux";   Arch="amd64"; Out="$binary-linux-amd64" },
        @{ OS="linux";   Arch="arm64"; Out="$binary-linux-arm64" },
        @{ OS="darwin";  Arch="arm64"; Out="$binary-darwin-arm64" },
        @{ OS="darwin";  Arch="amd64"; Out="$binary-darwin-amd64" },
        @{ OS="windows"; Arch="amd64"; Out="$binary-windows-amd64.exe" }
    )
    foreach ($p in $platforms) {
        Write-Host "Building $($p.Out)..."
        $env:GOOS = $p.OS; $env:GOARCH = $p.Arch; $env:CGO_ENABLED = "0"
        & $go build -ldflags $ldflags -o "$dist/$($p.Out)" ./cmd/agentd
        if (-not $?) { Remove-Item Env:\GOOS, Env:\GOARCH, Env:\CGO_ENABLED -ErrorAction SilentlyContinue; exit 1 }
    }
    Remove-Item Env:\GOOS, Env:\GOARCH, Env:\CGO_ENABLED -ErrorAction SilentlyContinue

    # Copy binaries and install.sh into BE/agents-dist so the server can serve them
    Write-Host "Copying to $beDist ..."
    Copy-Item "$dist\*" $beDist -Force
    Copy-Item "install.sh" $beDist -Force

    Write-Host "Build complete! Binaries in ./$dist/ and $beDist"
}

function Run-Clean {
    Remove-Item -Recurse -Force $dist -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $beDist -ErrorAction SilentlyContinue
    Write-Host "Cleaned $dist/ and $beDist"
}

switch ($target) {
    "build"     { Run-Build }
    "build-all" { Run-BuildAll }
    "tidy"      { Run-Tidy }
    "clean"     { Run-Clean }
    default     { Write-Host "Usage: .\build.ps1 [build|build-all|tidy|clean]" }
}
