param($user, $pass, $command)

function Create-RemoteTask{
    param([Management.Automation.PsCredential]$Credential)
    if($Credential.GetNetworkCredential().Password.length -gt 0){
        schtasks /CREATE /TN 'Temp Remote Task' /SC WEEKLY /RL HIGHEST `
            /RU "$($Credential.UserName)" /IT /RP $Credential.GetNetworkCredential().Password `
        /TR "powershell -noprofile -ExecutionPolicy Bypass -File $env:temp\RemoteTask.ps1" /F |
            Out-Null

        #Give task a normal priority
        $taskFile = Join-Path $env:TEMP RemotingTask.txt
        Remove-Item $taskFile -Force -ErrorAction SilentlyContinue
        [xml]$xml = schtasks /QUERY /TN 'Temp Remote Task' /XML
        $xml.Task.Settings.Priority="4"
        $xml.Save($taskFile)
        schtasks /CREATE /TN 'Remote Task' /RU "$($Credential.UserName)" /IT /RP $Credential.GetNetworkCredential().Password /XML "$taskFile" /F | Out-Null
        schtasks /DELETE /TN 'Temp Remote Task' /F | Out-Null
    }
    elseif(!((schtasks /QUERY /TN 'Remote Task' /FO LIST 2>&1) -contains 'Logon Mode:    Interactive/Background')) { #For testing
        schtasks /CREATE /TN 'Remote Task' /SC WEEKLY /RL HIGHEST `
                /RU "$($Credential.UserName)" /IT `
        /TR "powershell -noprofile -ExecutionPolicy Bypass -File $env:temp\RemoteTask.ps1" /F |
                Out-Null
    }
    if($LastExitCode -gt 0){
        throw "Unable to create scheduled task as $($Credential.UserName)"
    }
}

function Invoke-FromTask {
    param(
        $command, 
        $idleTimeout=60,
        $totalTimeout=3600
    )
    Add-TaskFiles $command

    $taskProc = start-Task

    if($taskProc -ne $null){
        write-debug "Command launched in process $taskProc"
        try { 
            $waitProc=get-process -id $taskProc -ErrorAction Stop 
            Write-Debug "Waiting on $($waitProc.Id)"
        } catch { $global:error.RemoveAt(0) }
    }

    Wait-ForTask $waitProc $idleTimeout $totalTimeout

    try{$errorStream=Import-CLIXML $env:temp\RemoteError.stream} catch {$global:error.RemoveAt(0)}
    $str=($errorStream | Out-String)
    if($str.Length -gt 0){
        throw $errorStream
    }
}

function Get-ChildProcessMemoryUsage {
    param($ID=$PID)
    [int]$res=0
    Get-WmiObject -Class Win32_Process -Filter "ParentProcessID=$ID" | % { 
        if($_.ProcessID -ne $null) {
            try {
                $proc = Get-Process -ID $_.ProcessID -ErrorAction Stop
                $res += $proc.PrivateMemorySize + $proc.WorkingSet
                Write-Debug "$($_.Name) $($proc.PrivateMemorySize + $proc.WorkingSet)"
            } catch { $global:error.RemoveAt(0) }
        }
    }
    Get-WmiObject -Class Win32_Process -Filter "ParentProcessID=$ID" | % { 
        if($_.ProcessID -ne $null) {
            try {
                $proc = Get-Process -ID $_.ProcessID -ErrorAction Top
                $res += Get-ChildProcessMemoryUsage $_.ProcessID;
                Write-Debug "$($_.Name) $($proc.PrivateMemorySize + $proc.WorkingSet)"
            } catch { $global:error.RemoveAt(0) }
        }
    }
    $res
}

function Add-TaskFiles($command) {
    $fileContent=@"
Start-Process powershell -Wait -RedirectStandardError $env:temp\RemoteError.stream -RedirectStandardOutput $env:temp\RemoteOutput.stream -WorkingDirectory '$PWD' -ArgumentList "-noprofile -ExecutionPolicy Bypass -EncodedCommand $command"
Remove-Item $env:temp\RemoteTask.ps1 -ErrorAction SilentlyContinue
"@
    Set-Content $env:temp\RemoteTask.ps1 -value $fileContent -force
    new-Item $env:temp\RemoteOutput.stream -Type File -Force | out-null
    new-Item $env:temp\RemoteError.stream -Type File -Force | out-null
}

function start-Task{
    $tasks=@()
    $tasks+=gwmi Win32_Process -Filter "name = 'powershell.exe' and CommandLine like '%-EncodedCommand%'" | select ProcessId | % { $_.ProcessId }
    Write-Debug "Found $($tasks.Length) tasks already running"
    $taskResult = schtasks /RUN /I /TN 'Remote Task'
    if($LastExitCode -gt 0){
        throw "Unable to run scheduled task. Message from task was $taskResult"
    }
    write-debug "Launched task. Waiting for task to launch command..."
    do{
        if(!(Test-Path $env:temp\RemoteTask.ps1)){
            Write-Debug "Task Completed before its process was captured."
            break
        }
        $taskProc=gwmi Win32_Process -Filter "name = 'powershell.exe' and CommandLine like '%-EncodedCommand%'" | select ProcessId | % { $_.ProcessId } | ? { !($tasks -contains $_) }

        Start-Sleep -Second 1
    }
    Until($taskProc -ne $null)

    return $taskProc
}

function Test-TaskTimeout($waitProc, $idleTimeout) {
    if($memUsageStack -eq $null){
        $script:memUsageStack=New-Object -TypeName System.Collections.Stack
    }
    if($idleTimeout -gt 0){
        $lastMemUsageCount=Get-ChildProcessMemoryUsage $waitProc.ID
        Write-Debug "Memory read: $lastMemUsageCount"
        Write-Debug "Memory count: $($memUsageStack.Count)"
        $memUsageStack.Push($lastMemUsageCount)
        if($lastMemUsageCount -eq 0 -or (($memUsageStack.ToArray() | ? { $_ -ne $lastMemUsageCount }) -ne $null)){
            $memUsageStack.Clear()
        }
        if($memUsageStack.Count -gt $idleTimeout){
            KillTree $waitProc.ID
            throw "TASK:`r`n$command`r`n`r`nIs likely in a hung state."
        }
    }
    Start-Sleep -Second 1
}

function Wait-ForTask($waitProc, $idleTimeout, $totalTimeout){
    $reader=New-Object -TypeName System.IO.FileStream -ArgumentList @(
        "$env:temp\RemoteOutput.Stream",
        [system.io.filemode]::Open,[System.io.FileAccess]::ReadWrite,
        [System.IO.FileShare]::ReadWrite)
    try{
        $procStartTime = $waitProc.StartTime
        while($waitProc -ne $null -and !($waitProc.HasExited)) {
            $timeTaken = [DateTime]::Now.Subtract($procStartTime)
            if($totalTimeout -gt 0 -and $timeTaken.TotalSeconds -gt $totalTimeout){
                KillTree $waitProc.ID
                throw "TASK:`r`n$command`r`n`r`nIs likely in a hung state."
            }

            $byte = New-Object Byte[] 100
            $count=$reader.Read($byte,0,100)
            if($count -ne 0){
                $text = [System.Text.Encoding]::Default.GetString($byte,0,$count)
                #$text | Out-File $boxstarter.Log -append
                $text | write-host -NoNewline
            }
            else {
                Test-TaskTimeout $waitProc $idleTimeout
            }
        }
        Start-Sleep -Second 1
        Write-Debug "Proc has exited: $($waitProc.HasExited) or Is Null: $($waitProc -eq $null)"
        $byte=$reader.ReadByte()
        $text=$null
        while($byte -ne -1){
            $text += [System.Text.Encoding]::Default.GetString($byte)
            $byte=$reader.ReadByte()
        }
        if($text -ne $null){
            #$text | out-file $boxstarter.Log -append
            $text | write-host -NoNewline
        }
    }
    finally{
        $reader.Dispose()
        if($waitProc -ne $null -and !$waitProc.HasExited){
            KillTree $waitProc.ID
        }
    }    
}

function KillTree($id){
    Get-WmiObject -Class Win32_Process -Filter "ParentProcessID=$ID" | % { 
        if($_.ProcessID -ne $null) {
            Invoke-SilentKill $_.ProcessID
            Write-Debug "Killing $($_.Name)"
            KillTree $_.ProcessID
        }
    }
    Invoke-SilentKill $id
}

function Invoke-SilentKill($id) {
    try {Kill $id -ErrorAction Stop -Force } catch { $global:error.RemoveAt(0) }
}

$secure = ConvertTo-SecureString $pass -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ($user, $secure)

Create-RemoteTask $creds
Invoke-FromTask -Command $command 
