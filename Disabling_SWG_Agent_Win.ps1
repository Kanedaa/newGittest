do {
$port = 5002

$searchProcess = netstat -ano | findstr :$port
$portPattern = ":$port\s.+0.0.0.0.0\s.+LISTENING\s+\d+$"
$pidPattern = "\d+$"


IF ($searchProcess | Select-String -Pattern $portPattern -Quiet) {
  $matches = $searchProcess | Select-String -Pattern $portPattern
  $firstMatch = $matches.Matches.Get(0).Value

  $pidNumber = [regex]::match($firstMatch, $pidPattern).Value

  $killMe = taskkill /pid $pidNumber /f

Write-Host Your Cisco Secure Client SWG Agent was stopped. To start it press CTRL+C.
}
} until ($pidNumber > 0)


