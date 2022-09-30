if (($Env:GHIDRA_HEADLESS -eq $null) -or (-not(Test-Path -Path $Env:GHIDRA_HEADLESS))) {
    Write-Host "ERROR: Unable to process this task. Please set the bash variable for GHIDRA_HEADLESS path"
    exit 0
}

$proj_loc="$($args[0])\ghidra_mods\ghidra_proj"
$script_fold="$($args[0])\ghidra_mods"
$script="$($args[0])\ghidra_mods\GenerateFuncAST.java"

Start-Process $Env:GHIDRA_HEADLESS -Wait -ArgumentList "$($proj_loc) Evolution -process $($args[1]) -scriptPath $($script_fold) -postScript $script $($args[0]) $('{0:x}' -f $args[2]) $($args[3]) -noanalysis -readOnly"

# Start-Process $Env:GHIDRA_HEADLESS -Wait -ArgumentList "$($proj_loc) Evolution -process $($args[1]) -scriptPath $($script_fold) -postScript $script $($args[0]) $($args[2]) $($args[3]) -noanalysis -readOnly"


