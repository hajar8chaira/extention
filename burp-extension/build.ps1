$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$source = Join-Path $root "src\main\java"
$classes = Join-Path $root "build\classes"
$output = Join-Path $root "build\security-center-burp.jar"
$libraryDirectory = Join-Path $root "lib"
$montoyaJar = Join-Path $libraryDirectory "montoya-api-2026.7.jar"
$compileMontoyaJar = $montoyaJar
$montoyaUrl = "https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/2026.7/montoya-api-2026.7.jar"
$jdk = "C:\Program Files\Java\jdk-21\bin"

if (-not (Test-Path (Join-Path $jdk "javac.exe"))) {
    throw "JDK 21 introuvable. Installez JDK 21 ou adaptez `$jdk dans build.ps1."
}

New-Item -ItemType Directory -Force -Path $libraryDirectory, $classes | Out-Null
if (-not (Test-Path $montoyaJar)) {
    Write-Host "Téléchargement de l'API Montoya officielle 2026.7..."
    Invoke-WebRequest -UseBasicParsing -Uri $montoyaUrl -OutFile $montoyaJar
}
Remove-Item -Recurse -Force $classes -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $classes | Out-Null
$sources = Get-ChildItem -Path $source -Filter *.java -Recurse | ForEach-Object FullName
& (Join-Path $jdk "javac.exe") --release 21 -encoding UTF-8 -cp $compileMontoyaJar -d $classes $sources
if ($LASTEXITCODE -ne 0) { throw "La compilation Java a échoué." }

New-Item -ItemType Directory -Force -Path (Split-Path $output) | Out-Null
& (Join-Path $jdk "jar.exe") --create --file $output -C $classes .
if ($LASTEXITCODE -ne 0) { throw "La création du JAR a échoué." }

Write-Host "Connecteur créé : $output"
