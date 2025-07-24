<# 
Chain.ps1 - cmd → powershell → cmd → SYSTEM notepad.exe 
관리자 PowerShell로 실행하세요.
#>

param(
    [string]$TaskName = "TempElevTask_$([guid]::NewGuid().ToString('N').Substring(0,8))"
)

# 마지막 cmd에서 SYSTEM 권한 예약 작업 수행
$finalCmd = @(
    "schtasks /Create /TN $TaskName /TR `"notepad.exe`" /SC ONCE /ST 00:00 /RL HIGHEST /RU SYSTEM /F",
    "schtasks /Run /TN $TaskName",
    "timeout /t 3 > nul",
    "schtasks /Delete /TN $TaskName /F"
) -join " & "

# PowerShell에서 실행할 명령
$psCmd = "Start-Process cmd.exe -ArgumentList '/c $finalCmd' -WindowStyle Hidden"

# 첫 번째 cmd 안에서 실행할 PowerShell 명령
$cmdCmd = "powershell.exe -Command `"$psCmd`""

# PowerShell → cmd → PowerShell → cmd → SYSTEM notepad 실행
Start-Process cmd.exe -ArgumentList "/c $cmdCmd" -WindowStyle Hidden

Write-Host "`n[+] cmd → powershell → cmd → SYSTEM notepad 실행 시도 완료"
Start-Sleep 5
Write-Host "[*] 종료 – 이벤트 로그 확인 필요"
