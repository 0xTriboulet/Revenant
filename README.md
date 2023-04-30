# Revenant  

Revenant is a 3rd party agent for Havoc written in C, and based on Talon. This implant is meant to expand on the Talon implant by implementing covert methods of execution, robust capabilities, and more customization.

This project aims to be a self-contained Havoc C2 implant. The goal end-user functionality is as follows:

## Setup
> 1) Download repo
> 2) Unzip Revenant.zip
> 3) Go to root folder
> 4) Execute python Revenant.py
> 5) ???
> 6) PROFIT

  > **Win7/8 Compatability:**  
  > - Disable NativeAPI
  >>Note: Currently Revenant uses NtCreateUserProcess to deliver NativeAPI functionality. NtCreateUserProcess is not supported by Win7/8.

## Commands
> - **shell** _executes commands through cmd.exe_ -> shell ls  
> - **download** _downloads file to loot folder_  -> download C:\test.txt   
> - **upload** - _uploads file to desired folder_ -> upload /home/test.txt C:\temp\test.txt  
> - **exit** - kills current implant    

### TODO:
> - Add additional commands
> - Decrease entropy  



![IMG_0314](https://user-images.githubusercontent.com/22229087/233796939-96a6100e-bcfc-4d4a-b1cb-c9eacdea6bf9.PNG)
