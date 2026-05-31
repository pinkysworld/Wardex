param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet("archive", "binary")]
    [string]$Mode,

    [Parameter(Mandatory = $true, Position = 1)]
    [string]$PrimaryPath,

    [Parameter(Mandatory = $false, Position = 2)]
    [string]$SiteDir
)

$ErrorActionPreference = "Stop"
$timeoutSeconds = if ($env:WARDEX_RELEASE_SMOKE_TIMEOUT_SECS) { [int]$env:WARDEX_RELEASE_SMOKE_TIMEOUT_SECS } else { 90 }
$tmpRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("wardex-release-smoke-" + [guid]::NewGuid().ToString("N"))
$serverProcess = $null

function Cleanup {
    if ($script:serverProcess) {
        try {
            Stop-Process -Id $script:serverProcess.Id -Force -ErrorAction SilentlyContinue
        } catch {
        }
    }
    if (Test-Path $script:tmpRoot) {
        Remove-Item -Recurse -Force $script:tmpRoot
    }
}

try {
    New-Item -ItemType Directory -Path $tmpRoot | Out-Null

    function New-RandomToken {
        $bytes = New-Object byte[] 32
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
        return -join ($bytes | ForEach-Object { $_.ToString("x2") })
    }

    function New-FreePort {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $listener.Start()
        $port = ($listener.LocalEndpoint).Port
        $listener.Stop()
        return $port
    }

    function Wait-Http {
        param(
            [string]$Url,
            [hashtable]$Headers = @{}
        )

        $deadline = (Get-Date).AddSeconds($timeoutSeconds)
        while ((Get-Date) -lt $deadline) {
            try {
                Invoke-WebRequest -Uri $Url -Headers $Headers -UseBasicParsing | Out-Null
                return
            } catch {
                Start-Sleep -Seconds 1
            }
        }
        throw "Timed out waiting for $Url"
    }

    function Run-BinarySmoke {
        param(
            [string]$BinaryPath,
            [string]$WorkDir
        )

        $configDir = Join-Path $WorkDir "var"
        $configPath = Join-Path $configDir "wardex.toml"
        $doctorPath = Join-Path $WorkDir "doctor.txt"
        $stdoutPath = Join-Path $WorkDir "server.stdout.log"
        $stderrPath = Join-Path $WorkDir "server.stderr.log"
        $port = New-FreePort
        $token = New-RandomToken

        New-Item -ItemType Directory -Force -Path $configDir | Out-Null
        & $BinaryPath --version | Out-Null

        $oldConfig = $env:WARDEX_CONFIG_PATH
        try {
            $env:WARDEX_CONFIG_PATH = $configPath
            & $BinaryPath init-config $configPath | Out-Null
            Push-Location $WorkDir
            try {
                & $BinaryPath doctor | Out-File -Encoding utf8 $doctorPath
            } finally {
                Pop-Location
            }

            $env:WARDEX_ADMIN_TOKEN = $token
            $script:serverProcess = Start-Process -FilePath $BinaryPath `
                -ArgumentList @("serve", "$port", "site") `
                -WorkingDirectory $WorkDir `
                -PassThru `
                -RedirectStandardOutput $stdoutPath `
                -RedirectStandardError $stderrPath

            Wait-Http -Url "http://127.0.0.1:$port/admin/"
            Wait-Http -Url "http://127.0.0.1:$port/api/healthz/ready" -Headers @{ Authorization = "Bearer $token" }
            Wait-Http -Url "http://127.0.0.1:$port/api/support/bundle" -Headers @{ Authorization = "Bearer $token" }

            Stop-Process -Id $script:serverProcess.Id -Force
            $script:serverProcess = $null
        } finally {
            if ($null -eq $oldConfig) {
                Remove-Item Env:WARDEX_CONFIG_PATH -ErrorAction SilentlyContinue
            } else {
                $env:WARDEX_CONFIG_PATH = $oldConfig
            }
            Remove-Item Env:WARDEX_ADMIN_TOKEN -ErrorAction SilentlyContinue
        }
    }

    switch ($Mode) {
        "archive" {
            $artifactPath = (Resolve-Path $PrimaryPath).Path
            $extractRoot = Join-Path $tmpRoot "archive"
            Expand-Archive -Path $artifactPath -DestinationPath $extractRoot
            $binary = Get-ChildItem -Path $extractRoot -Recurse -Filter "wardex.exe" | Select-Object -First 1
            if (-not $binary) {
                throw "Could not find wardex.exe in $artifactPath"
            }
            $archiveRoot = $binary.Directory.FullName
            if (-not (Test-Path (Join-Path $archiveRoot "site"))) {
                throw "Archive root '$archiveRoot' does not contain site/"
            }
            Run-BinarySmoke -BinaryPath $binary.FullName -WorkDir $archiveRoot
        }
        "binary" {
            if (-not $SiteDir) {
                throw "binary mode requires <site_dir>"
            }
            $binaryPath = (Resolve-Path $PrimaryPath).Path
            $resolvedSite = (Resolve-Path $SiteDir).Path
            $workDir = Join-Path $tmpRoot "binary"
            New-Item -ItemType Directory -Path $workDir | Out-Null
            Copy-Item -Recurse $resolvedSite (Join-Path $workDir "site")
            Run-BinarySmoke -BinaryPath $binaryPath -WorkDir $workDir
        }
    }
} finally {
    Cleanup
}
