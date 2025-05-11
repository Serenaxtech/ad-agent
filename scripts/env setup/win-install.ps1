# Install Python 3.11
$pythonUrl = "https://www.python.org/ftp/python/3.11.8/python-3.11.8-amd64.exe"
$installer = "$env:TEMP\python-installer.exe"
Invoke-WebRequest $pythonUrl -OutFile $installer
Start-Process -Wait $installer -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1"

# Refresh PATH
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine")

# Install Poetry
(Invoke-WebRequest -Uri https://install.python-poetry.org -UseBasicParsing).Content | python -

# Add Poetry to PATH (if not already)
$poetryPath = "$env:APPDATA\Python\Scripts"
if (-Not ($env:Path -like "*$poetryPath*")) {
    [System.Environment]::SetEnvironmentVariable("Path", $env:Path + ";$poetryPath", "User")
    Write-Output "✅ Poetry path added to user PATH. Restart terminal to apply."
}

Write-Output "`n🎉 Python 3.11 and Poetry installed successfully."
