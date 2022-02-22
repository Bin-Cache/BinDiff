# Tracking Changes in Firmware Update Packages

## Installation

### Install Project Dependencies:
```
$ pip install -r requirements.txt
```

### Install Ghidra
* Install JDK 11 64-bit https://www.oracle.com/java/technologies/downloads/#java11
* Download a Ghidra release file : https://github.com/NationalSecurityAgency/ghidra/releases
* Extract the Ghidra release file
* Launch Ghidra: `./ghidraRun` (or `ghidraRun.bat` for Windows)

### Set Ghidra Headless Program Environment Variable
Set an environment variable named GHIDRA_HEADLESS pointing to the ghidra's headless program in your ghidra installation folder 
[Ghidra Installation Folder]/support/analyzeHeadless

See Pipeline.ipynb for example.


## Run
In the Project Directory run jupyter notebook
```
$ jupyter notebook
```
Once the notebook is active, open the Pipeline.ipynb file and run all cells to get the latest results for the project.
For Mac Users allow the decompile program to run.


## Results
All results can be found in the versions folder.
 
