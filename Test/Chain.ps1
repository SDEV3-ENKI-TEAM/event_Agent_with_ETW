<#
Chain.ps1
cmd → powershell → cmd → SYSTEM 권한으로 notepad.exe, calc.exe 실행
모든 창은 사용자 확인을 위해 Visible (숨기지 않음)
관리자 PowerShell에서 실행할 것
#>

param(
    [string]$TaskName = "TempElevTask_$([guid]::NewGuid().ToString('N').Substring(0,8))"
)

# 최종 cmd에서 실행할 SYSTEM 예약 작업 명령어
$finalCmd = @(
    "schtasks /Create /TN $TaskName /TR \"powershell.exe -Command \\\"Start-Process notepad.exe; Start-Process calc.exe\\\"\" /SC ONCE /ST 00:00 /RL HIGHEST /RU SYSTEM /F",
    "schtasks /Run /TN $TaskName",
    "timeout /t 5 > nul",
    "schtasks /Delete /TN $TaskName /F"
) -join " & "

# 중간 PowerShell이 실행할 cmd 명령
$psCmd = "Start-Process cmd.exe -ArgumentList '/k $finalCmd' -WindowStyle Normal"

# 첫 번째 cmd가 실행할 PowerShell 명령
$cmdCmd = "powershell.exe -NoExit -Command \"$psCmd\""

# 최상위: PowerShell → cmd (창 표시)
Start-Process cmd.exe -ArgumentList "/k $cmdCmd" -WindowStyle Normal

Write-Host "`n[+] cmd → powershell → cmd → SYSTEM 예약 작업 실행 시도 완료 (모든 단계에서 창 표시)"
Start-Sleep 5
Write-Host "[*] 종료 – 각 창에서 실행된 작업 확인"
