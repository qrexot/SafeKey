$ErrorActionPreference = "Stop"

$port = 5173

Write-Host "Serving on http://localhost:$port/ (Ctrl+C to stop)"

if (Get-Command python -ErrorAction SilentlyContinue) {
  python -m http.server $port
  exit $LASTEXITCODE
}

if (Get-Command py -ErrorAction SilentlyContinue) {
  py -m http.server $port
  exit $LASTEXITCODE
}

throw "Python не найден. Установите Python или запустите любой статический HTTP-сервер в папке проекта."

