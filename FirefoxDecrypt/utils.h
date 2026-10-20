#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <string>
#include <vector>
#include <optional>
#include <iostream>

struct SECItem {
    int type;
    unsigned char* data;
    unsigned int len;
};

struct PK11SlotInfoStr;
using PK11SlotInfo = PK11SlotInfoStr;
using PK11PasswordFunc = char* (__cdecl*)(PK11SlotInfo*, int, void*);

using NSSInitFn = int(__cdecl*)(const char*);
using NSSShutdownFn = int(__cdecl*)();
using PK11SDRDecryptFn = int(__cdecl*)(SECItem*, SECItem*, void*);
using SECItemZfreeItemFn = void(__cdecl*)(SECItem*, int);
using PK11SetPasswordFuncFn = void(__cdecl*)(PK11PasswordFunc);
using PORTStrdupFn = char* (__cdecl*)(const char*);

//PORTStrdupFn g_portStrdup = nullptr;

struct Login {
    std::string hostname;
    std::string encryptedUsername;
    std::string encryptedPassword;
};

struct JsonResult {
    std::optional<std::string> stringValue;
    std::vector<Login> logins;
};

void AppendUtf8(std::string& output, unsigned int codePoint);

std::vector<unsigned char> DecodeBase64(const std::string& input);

std::string WideToUtf8(const std::wstring& value);

//template <typename T>
//bool LoadFunction(HMODULE module, const char* name, T& function);
template <typename T>
bool LoadFunction(HMODULE module, const char* name, T& function)
{
    function = reinterpret_cast<T>(GetProcAddress(module, name));
    if (function)
        return true;
    std::cerr << "Missing NSS export: " << name << '\n';
    return false;
}
std::string GetWindowsError(DWORD error);