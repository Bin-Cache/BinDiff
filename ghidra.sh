OUT_FILE='graphA.json' /Users/wamuo/Documents/Lab/tools/ghidra_9.2/support/analyzeHeadless /Users/wamuo/Documents/Lab/Projects/ghidra_proj 'ARM Galore' -process otaApp-113.199.8.bin -scriptPath /Users/wamuo/Documents/Lab/Projects/FunctionPeripheralSequence -postScript reference_trace.py -noanalysis -readOnly
OUT_FILE='graphB.json' /Users/wamuo/Documents/Lab/tools/ghidra_9.2/support/analyzeHeadless /Users/wamuo/Documents/Lab/Projects/ghidra_proj 'ARM Galore' -process otaApp-1.5.10008.bin -scriptPath /Users/wamuo/Documents/Lab/Projects/FunctionPeripheralSequence -postScript reference_trace.py -noanalysis -readOnly

# OUT_FILE='graphB.json' /Users/wamuo/Documents/Lab/tools/ghidra_9.2/support/analyzeHeadless /Users/wamuo/Documents/Lab/Projects/ghidra_proj 'ARM Galore' -process http_client_demo1_1.bin -scriptPath /Users/wamuo/Documents/Lab/Projects/FunctionPeripheralSequence -postScript reference_trace.py -noanalysis -readOnly

# python compare.py
