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

#Requires -RunAsAdministrator

$ErrorActionPreference = 'Stop'
$CurrentNightlyUrl = "https://get-nats.io/current-nightly"
$PlatformsUrl = "https://get-nats.io/synadia-nats-platforms.json"
$NATSDir = "NATS"
$OSInfo = "windows-amd64"
$Stable = "stable"
$Nightly = "nightly"
$NscTool = "nsc"
$NscExe = "nsc.exe"
$NscZip = "nsc.zip"

# ----------------------------------------------------------------------------------------------------
# Functions
# ----------------------------------------------------------------------------------------------------
Function Read-NightlyVersion() {
	if (!$_currentNightly) {
		$temp = [string](Invoke-WebRequest -Uri $CurrentNightlyUrl)
		$_currentNightly = $temp.Split("`r?`n")[0]
	}
	return $_currentNightly
}

Function Format-EndWithBackslash($s) {
	if ($s.EndsWith("\")){
		return $s
	}
	return $s + "\"
}

Function Format-DoesntEndWithBackslash($s) {
	if ($s.EndsWith("\")){
		return $s.Substring(0, $s.Length - 1)
	}
	return $s
}

Function Select-Folder() {
	[void] [System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
	$FolderBrowserDialog = New-Object System.Windows.Forms.FolderBrowserDialog
	$FolderBrowserDialog.RootFolder = 'MyComputer'
	[void] $FolderBrowserDialog.ShowDialog()
	return $FolderBrowserDialog.SelectedPath
}

Function Invoke-Backup($BinDir, $Tool, $ExePath) {
	if ( Test-Path $ExePath )
	{
		Write-Host "Backing up existing $Tool executable..."
		for($i = 1; $i -lt 100; $i++) # I give up after 99 tries
		{
			$nn = "$BinDir$Tool-" + (Get-Date -Format "yyyyMMdd") + "-backup$i.exe"
			if (!(Test-Path $nn))
			{
				Rename-Item -Path $ExePath -NewName $nn
				return
			}
		}
		Write-Host "Cannot backup $ExePath, all backups exist."
		Exit -2
	}
}

# ----------------------------------------------------------------------------------------------------
# Execution
# ----------------------------------------------------------------------------------------------------
# They get to pick the folder given a default
$tempDir = (Format-EndWithBackslash $Env:ProgramFiles) + $NATSDir
$opt0 = New-Object System.Management.Automation.Host.ChoiceDescription "&Default Location","Default Location is $tempDir"
$opt1 = New-Object System.Management.Automation.Host.ChoiceDescription "&Choose Location","Choose your location."
$options = [System.Management.Automation.Host.ChoiceDescription[]]($opt0, $opt1)
$result = $host.ui.PromptForChoice("Installation Location", "Where will the programs be installed? Default Location is $tempDir", $options, 0)
if ($result -eq 1) {
	$tempDir = Select-Folder
	if (!$tempDir) {
		Write-Host "You must pick a directory. Exiting"
		Exit -1
	}
}
$binDir = Format-EndWithBackslash $tempDir
$binDirNoSlash = Format-DoesntEndWithBackslash $binDir
if ( !(Test-Path $binDirNoSlash) ) {
	New-Item $binDirNoSlash -ItemType Directory | Out-Null
}

# some local variables now that I have $binDir
$nscExePath = $binDir + $NscExe
$nscZipLocal =  $binDir + $NscZip

# $channel Have the user pick which type of channel they want, i.e. stable or nightly.
$opt0 = New-Object System.Management.Automation.Host.ChoiceDescription "&$Stable","Latest Stable Build."
$opt1 = New-Object System.Management.Automation.Host.ChoiceDescription "&$Nightly","Current Nightly Build."
$options = [System.Management.Automation.Host.ChoiceDescription[]]($opt0, $opt1)
$result = $host.ui.PromptForChoice("$Channel Selection", "Which channel do you want to install?", $options, 0)
switch ($result) {
	0{$channel = $Stable}
	1{$channel = $Nightly}
}
Write-Host ""

# Add bin dir to path if not already in path
Write-Host "Ensuring $binDirNoSlash is in the path..."
$Machine = [EnvironmentVariableTarget]::Machine
$Path = [Environment]::GetEnvironmentVariable('Path', $Machine)
if (!(";$Path;".ToLower() -like "*;$binDirNoSlash;*".ToLower())) {
	[Environment]::SetEnvironmentVariable('Path', "$Path;$binDirNoSlash", $Machine)
	$Env:Path += ";$binDirNoSlash"
}

Write-Host "Downloading platform info..."
$json = (Invoke-WebRequest https://get-nats.io/synadia-nats-platforms.json -ContentType "application/json" -UseBasicParsing) | ConvertFrom-Json
$nscZipUrl = $json.$channel.platforms.$OSInfo.tools.$NscTool.zip_url

if ($channel -eq $Nightly) {
	$verNsc = Read-NightlyVersion
	Write-Host "$NscTool $Nightly version $verNsc"
	$nscZipUrl = $nscZipUrl.Replace("%NIGHTLY%", $verNsc)
}
else {
	$verNsc = $json.$channel.platforms.$OSInfo.tools.$NscTool."version_tag"
	Write-Host "$NscTool $Stable version $verNsc"
}

# Download the zip files
Write-Host "Downloading archive $nscZipUrl..."
Invoke-WebRequest -Uri $nscZipUrl -OutFile $nscZipLocal -UseBasicParsing

# Backup existing versions now that the downloads worked
Invoke-Backup $binDir $NscTool $nscExePath

# nsc: Unzip, Remove Archive
Write-Host "Installing $NscTool..."
Expand-Archive -Path $nscZipLocal -DestinationPath $binDir
Remove-Item $nscZipLocal

Write-Host "Done!`r`n"
