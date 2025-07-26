Write-Host "[*] EventLogWatcher 테스트용 스크립트 시작"

# 1. 로그온 실패 유도 (4625)
Start-Process "runas.exe" -ArgumentList "/user:FakeUser cmd.exe"

# 2. 자격 증명 사용 로그온 시도 (4648)
try {
    runas /user:Administrator powershell
} catch {
    Write-Host "[!] runas 실패 (4648 예상)"
}

# 3. 특권 로그온 유도 (4672)
try {
    Start-Process powershell -Verb RunAs -ArgumentList "-Command `"whoami`""
} catch {
    Write-Host "[!] 권한 상승 시도 실패 (권한 상승 실패는 무시됨)"
}

# 4. 파일 시스템 접근 감사 유도 (4663) – 감사 정책이 설정된 경우에만 감지됨
$path = "$env:TEMP\etw_test_file.txt"
Set-Content $path "ETW test"
Get-Content $path | Out-Null
Remove-Item $path

# 5. 예약 작업 생성 및 삭제 (4698, 4699)
$taskName = "TestEventLogTask_$([guid]::NewGuid().ToString().Substring(0, 6))"
schtasks /Create /TN $taskName /TR "notepad.exe" /SC ONCE /ST 23:59 /RL HIGHEST /F | Out-Null
schtasks /Delete /TN $taskName /F | Out-Null

# 종료 대기
Read-Host "Press <Enter> to close test script"
