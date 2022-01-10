OUT_FILE='graphA.json' /Users/wamuo/Documents/Lab/tools/ghidra_9.2/support/analyzeHeadless /Users/wamuo/Documents/Lab/Projects/ghidra_proj 'ARM Galore' -process otaApp-1.4.2.bin -scriptPath /Users/wamuo/Documents/Lab/Projects/FunctionPeripheralSequence -postScript reference_trace.py -noanalysis -readOnly
OUT_FILE='graphB.json' /Users/wamuo/Documents/Lab/tools/ghidra_9.2/support/analyzeHeadless /Users/wamuo/Documents/Lab/Projects/ghidra_proj 'ARM Galore' -process otaApp-1.4.4.bin -scriptPath /Users/wamuo/Documents/Lab/Projects/FunctionPeripheralSequence -postScript reference_trace.py -noanalysis -readOnly

# OUT_FILE='graphB.json' /Users/wamuo/Documents/Lab/tools/ghidra_9.2/support/analyzeHeadless /Users/wamuo/Documents/Lab/Projects/ghidra_proj 'ARM Galore' -process http_client_demo1_1.bin -scriptPath /Users/wamuo/Documents/Lab/Projects/FunctionPeripheralSequence -postScript reference_trace.py -noanalysis -readOnly

# python compare.py
