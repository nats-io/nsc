# Copyright 2022 The NATS Authors
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

$ErrorActionPreference = 'Stop'

$Version = ""
if ($args.Length -eq 1) {
    $Version = $args.Get(0)
}

$NscInstall = $env:NSC_INSTALL
$BinDir = if ($NscInstall) {
    "$NscInstall\bin"
} else {
    "$Home\.nats\bin"
}

$NscZip = "$BinDir\nsc.zip"
$NscExe = "$BinDir\nsc.exe"
$Target = 'windows-amd64'

if (Test-Path "$BinDir\nsc.exe") {
	Write-Host "NSC binary ($BinDir\nsc.exe) already exists, exiting script.`r`n"
	Exit -1
}

if ( !(Test-Path $BinDir) ) {
    New-Item $BinDir -ItemType Directory | Out-Null
	Write-Host "NSC directory ($BinDir) created...`r`n"
}


# Download the archive with the exe from github
## GitHub requires TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

## Uri is different when a version is requested
if (!$Version) {
    Write-Host "Downloading latest nsc...`r`n"
    $NscUri = "https://github.com/nats-io/nsc/releases/latest/download/nsc-${Target}.zip"
} else {
    Write-Host "Downloading nsc version ${Version}...`r`n"
    $NscUri = "https://github.com/nats-io/nsc/releases/download/${Version}/nsc-${Target}.zip"
}

## Actual download
Invoke-WebRequest -Uri $NscUri -OutFile $NscZip -UseBasicParsing

## Unzip
Write-Host "Extracting nsc.exe...`r`n"
Expand-Archive -Path $NscZip -DestinationPath $BinDir

# Remove downloaded archive file
Write-Host "Removing downloaded archive...`r`n"
Remove-Item $NscZip

# Add bin dir to path if not already in path
Write-Host "Updating $BinDir for the User's path...`r`n"
$User = [EnvironmentVariableTarget]::User
$Path = [Environment]::GetEnvironmentVariable('Path', $User)
if (!(";$Path;".ToLower() -like "*;$BinDir;*".ToLower())) {
    [Environment]::SetEnvironmentVariable('Path', "$Path;$BinDir", $User)
    $Env:Path += ";$BinDir"
}

Write-Host "NSC was installed successfully to $NscExe. Running 'nsc --version' to verify...`r`n"
nsc --version

Write-Host "`r`nRun 'nsc --help' to get started.`r`n"
