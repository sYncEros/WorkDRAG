$ErrorActionPreference = "Stop"

$sourceRoot = "C:\Windows.old\Users\jnavaqui"
$destinationRoot = "E:\AI People\oldWin_preserved"

$itemsToCopy = @(
  "AppData\Local\Microsoft\Outlook",
  "AppData\Local\Microsoft\OneDrive",
  "AppData\Local\Microsoft\Edge",
  "AppData\Local\Microsoft\Olk",
  "AppData\Local\Microsoft\Team Foundation",
  "NTUSER.DAT",
  "ntuser.dat.LOG1",
  "ntuser.dat.LOG2"
)

if (-not (Test-Path -LiteralPath $sourceRoot)) {
  throw "No existe el origen: $sourceRoot"
}

New-Item -ItemType Directory -Force -Path $destinationRoot | Out-Null

foreach ($relativePath in $itemsToCopy) {
  $sourcePath = Join-Path $sourceRoot $relativePath
  $destinationPath = Join-Path $destinationRoot $relativePath

  if (-not (Test-Path -LiteralPath $sourcePath)) {
    Write-Warning "No encontrado: $sourcePath"
    continue
  }

  $destinationParent = Split-Path -Parent $destinationPath
  if ($destinationParent) {
    New-Item -ItemType Directory -Force -Path $destinationParent | Out-Null
  }

  Write-Host "Copiando $relativePath"

  if ((Get-Item -LiteralPath $sourcePath).PSIsContainer) {
    Copy-Item -LiteralPath $sourcePath -Destination $destinationPath -Recurse -Force
  } else {
    Copy-Item -LiteralPath $sourcePath -Destination $destinationPath -Force
  }
}

Write-Host ""
Write-Host "Copia completada."
Write-Host "Destino: $destinationRoot"
Write-Host "Este script no elimina nada del origen."
