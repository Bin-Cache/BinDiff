if (($Env:GHIDRA_HEADLESS -eq $null) -or (-not(Test-Path -Path $Env:GHIDRA_HEADLESS))) {
    Write-Host "ERROR: Unable to process this task. Please set the bash variable for GHIDRA_HEADLESS path"
    exit 0
}

$proj_loc="$($args[0])\ghidra_mods\ghidra_proj"
$script_fold="$($args[0])\ghidra_mods"
$script="$($args[0])\ghidra_mods\reference_trace.py"

$update_files=(Get-ChildItem -Filter "versions\*.bin").FullName


Start-Process $Env:GHIDRA_HEADLESS -Wait -ArgumentList "$($proj_loc) Evolution -import $($update_files) -loader BinaryLoader -loader-baseAddr 0x20004000 -loader-blockName app -processor ARM:LE:32:Cortex"
Start-Process $Env:GHIDRA_HEADLESS -Wait -ArgumentList "$($proj_loc) Evolution -process *.bin -scriptPath $($script_fold) -postScript $($script) $($args[0]) -noanalysis -readOnly"