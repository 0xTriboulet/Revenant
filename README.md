# Revenant  

Revenant is a 3rd party agent for Havoc written in C, and based on Talon. This implant is meant to expand on the Talon implant by implementing covert methods of execution, robust capabilities, and more customization.

This project aims to be a self-contained Havoc C2 implant. The goal end-user functionality is as follows:

### Setup
> 1) Download repo
> 2) Unzip Revenant.zip
> 3) pip install black
> 4) startup Havoc (./havoc server --profile ./profiles/havoc.yaotl -v --debug & ./havoc client )
> 5) Go to root folder
> 6) python Revenant.py
> 7) ???
> 8) PROFIT

  > **x86 and Win7/8 Compatability:**  
  > - Disable NativeAPI
  >>Note: Currently Revenant uses NtCreateUserProcess to deliver NativeAPI functionality. NtCreateUserProcess is not supported by x86 or Win7/8.
  

### Commands
> - **pwsh** - executes commands through powershell.exe -> pwsh ls
> - **shell** - executes commands through cmd.exe       -> shell dir  
> - **download** - downloads file to loot folder        -> download C:\test.txt   
> - **upload** - uploads file to desired folder         -> upload /home/test.txt C:\temp\test.txt  
> - **exit** - kills current implant                    -> exit

### Options
> - **Sleep** - Set sleep in seconds  
> - **Polymorphic** - Enable/Disable polymorphism at build and run time
> - **Obfuscation** - Obfuscate strings with XOR
> - **Arch** - x86/x64
> - **Native** - Use NativeAPI where implemented
> - **AntiDbg** - Leverage antidebug checks at initialization
> - **RandCmdIDs** - Randomize command IDs  
> - **Unhooking** - Perun's Fart method to unhook, exec command, then rehook 
>> Note: RandCmdIDs randomizes the CmdIDs in the output executable. Revenant does **NOT** store these random CmdIDs; these will only work with the active session. If you want a reusable executable, do **NOT** enable this option.

### TODO:
> - Add exec-assembly
> - Add cd, ls, whoami commands
> - Decrease entropy



![IMG_0314](https://user-images.githubusercontent.com/22229087/233796939-96a6100e-bcfc-4d4a-b1cb-c9eacdea6bf9.PNG)
