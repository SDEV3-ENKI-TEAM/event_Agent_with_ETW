<#
 ElevationChain.ps1
 ─────────────────────────────────────────
 1) 현재 PowerShell → cmd.exe 실행
 2) cmd.exe 안에서 ‘일회용’ 예약 작업을 SYSTEM 권한으로 등록
 3) 즉시 작업 실행 → taskeng.exe(SYSTEM) 가 notepad.exe 로 권한상승
 4) 3초 대기 후 작업 삭제
 ※ 관리자 PowerShell 로 실행해야 합니다.
#>

param(
    [string]$TaskName = "TempElevTask_$([guid]::NewGuid().ToString('N').Substring(0,8))"
)

# cmd.exe 한 줄짜리 스크립트 작성
$cmdLine = @(
    "schtasks /Create /TN $TaskName /TR `"notepad.exe`" /SC ONCE /ST 00:00 /RL HIGHEST /RU SYSTEM /F",
    "schtasks /Run    /TN $TaskName",
    "timeout /t 3 > nul",
    "schtasks /Delete /TN $TaskName /F"
) -join " & "

# ① PowerShell → ② cmd.exe
Start-Process cmd.exe -ArgumentList "/c $cmdLine" -WindowStyle Hidden
Write-Host "`n[+] cmd.exe 로 SYSTEM 예약 작업 생성·실행 요청 완료"

# (옵션) 완료 대기
Start-Sleep 5
Write-Host "[*] 스크립트 종료 – Sysmon·Security 로그 확인!"
