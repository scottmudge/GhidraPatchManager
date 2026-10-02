$ErrorActionPreference = 'Stop'
if (-not $env:GHIDRA_INSTALL_DIR) {
    throw 'Set GHIDRA_INSTALL_DIR to your Ghidra installation directory.'
}
if (Get-Command gradle -ErrorAction SilentlyContinue) {
    gradle buildExtension
} else {
    throw 'Gradle is not installed and no Gradle wrapper exists.'
}
