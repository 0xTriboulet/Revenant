# Revenant  

Revenant is a 3rd party agent for Havoc written in C, and based on Talon. This implant is meant to expand on the Talon implant by implementing covert methods of execution, robust capabilities, and more customization.

This project aims to be a self-contained Havoc C2 implant. The goal end-user functionality is as follows:

1) Download repo
2) Unzip Revenant.zip
3) Go to root folder
4) Execute python Revenant.py
5) ???
6) PROFIT

  > Win7/8 Compatability:  
  > - Disable NativeAPI  

> TODO:
> - Add additional commands
> - Obfuscate WinAPI calls when "Obfuscation" enabled
> - Encrypt/Obf Config.h
> - Decrease entropy  



![IMG_0314](https://user-images.githubusercontent.com/22229087/233796939-96a6100e-bcfc-4d4a-b1cb-c9eacdea6bf9.PNG)



The original Talon description can be found below.

-------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Talon is a 3rd party agent for Havoc written in C. It's very minimalistic and it's meant to show how to work with the Havoc service api.
Talon.py is the script that handles callbacks, register reqeuest and tasks by interacting with the Havoc service api. 

![Payload Generator](Assets/PayloadGenerator.png)
![Havoc Talon Interacted](Assets/HavocTalonInteract.png)

