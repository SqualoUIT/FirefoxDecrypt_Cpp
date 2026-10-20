# Firefox decrypt logins data [C++]
This project is intended for educational and research purposes only. Use it only with data you own or are explicitly authorized to access.

## Overview
This tool is used to decrypt logins data saved in firefox profile. Leverage Firefox's encryption and decryption methods via `nss3.dll`.

Using the functions exported in `nss3.dll` to decrypt the data. Drawing on my experience with C++ programming and reverse engineering, I determined the structure of the functions that needed to be called and proceeded to load their addresses using the WinAPI functions **LoadLibrary** and **GetProcAddress**.

## How It Works
Based on my research and reverse engineering, I discovered that the process for decrypting Firefox login data relies on `nss3.dll`. Consequently, I decided to leverage this DLL.

The goal is to utilize the functions exported by `nss3.dll`—calls the required NSS functions—to decrypt the data. The functions that need to be called include **NSS_Init**, **NSS_Shutdown**, **PK11SDR_Decrypt**, and **SECITEM_ZfreeItem**.

The tool loads `nss3.dll` from the Firefox installation folder and then proceeds to load the necessary functions. Next, it parses the JSON-formatted login data file from profile folder, decrypts the entries, and prints each login data field found within the JSON to the console.

## Usage
```
FirefoxDecrypt.exe <Firefox-install-folder> <Firefox-profile-folder>

<Firefox-install-folder>        Folder containing firefox.exe
                                Example: C:\Program Files\Mozilla Firefox
<Firefox-profile-folder>        The profile folder contains information
                                Example: C:\Users\TestUser\AppData\Roaming\Mozilla\Firefox\Profiles\<profile_name>

Ex: FirefoxDecrypt.exe "C:\Program Files\Mozilla Firefox" "C:\Users\TestUser\AppData\Roaming\Mozilla\Firefox\Profiles\2aijx2r3.default-release"
```