#include <iostream>
#include <filesystem>
#include <fstream>
#include "utils.h"
#include  "nss_decrypt.h"
#include "json.hpp"

int wmain(int argc, wchar_t* argv[]) {
    if (argc != 3) {
        std::wcerr << L"Usage: nss_sdr_demo.exe <Firefox-install-folder> "
            L"<Firefox-profile-folder>\n"
            L"Close Firefox before running this program. "
            L"Decrypted credentials are printed to the console.\n";
        return 2;
    }

    const std::filesystem::path firefoxFolder(argv[1]);
    const std::filesystem::path profile(argv[2]);
    if (!std::filesystem::is_directory(firefoxFolder) ||
        !std::filesystem::is_directory(profile)) {
        std::cerr << "Firefox install folder or profile folder does not exist.\n";
        return 2;
    }

    const std::filesystem::path nssPath = firefoxFolder / L"nss3.dll";
    const std::filesystem::path loginsPath = profile / L"logins.json";
    if (!std::filesystem::is_regular_file(nssPath) ||
        !std::filesystem::is_regular_file(loginsPath)) {
        std::cerr << "Expected nss3.dll and profile logins.json were not found.\n";
        return 2;
    }

    std::string configPath;
    //std::vector<Login> logins;
    using json = nlohmann::json;
    json jsondata;

    try 
    {
        configPath = GetNssConfigPath(profile);
        std::ifstream file(loginsPath, std::ios::binary);
        if (!file)
            throw std::runtime_error("Could not open profile logins.json.");
        const std::string jsonStr((std::istreambuf_iterator<char>(file)),
            std::istreambuf_iterator<char>());
        jsondata = json::parse(jsonStr);
    }
    catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }

    auto logins = jsondata["logins"];

    if (logins.empty()) {
        std::cout << "No saved logins found in this profile.\n";
        return 0;
    }

    if (!SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS |
        LOAD_LIBRARY_SEARCH_USER_DIRS)) {
        std::cerr << "SetDefaultDllDirectories failed: "
            << GetWindowsError(GetLastError()) << '\n';
        return 1;
    }
    DLL_DIRECTORY_COOKIE dllDirectory = AddDllDirectory(firefoxFolder.c_str());
    if (!dllDirectory) {
        std::cerr << "AddDllDirectory failed: "
            << GetWindowsError(GetLastError()) << '\n';
        return 1;
    }

    HMODULE nss = LoadLibraryExW(
        nssPath.c_str(), nullptr,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS |
        LOAD_LIBRARY_SEARCH_USER_DIRS);
    if (!nss) {
        std::cerr << "Could not load Firefox nss3.dll: "
            << GetWindowsError(GetLastError()) << '\n';
        RemoveDllDirectory(dllDirectory);
        return 1;
    }

    NSSInitFn nssInit = nullptr;
    NSSShutdownFn nssShutdown = nullptr;
    PK11SDRDecryptFn decrypt = nullptr;
    SECItemZfreeItemFn freeItem = nullptr;
    PK11SetPasswordFuncFn setPasswordFunc = nullptr;
    PORTStrdupFn portStrdup = nullptr;
    const bool exportsLoaded =
        LoadFunction(nss, "NSS_Init", nssInit) &&
        LoadFunction(nss, "NSS_Shutdown", nssShutdown) &&
        LoadFunction(nss, "PK11SDR_Decrypt", decrypt) &&
        LoadFunction(nss, "SECITEM_ZfreeItem", freeItem) &&
        LoadFunction(nss, "PK11_SetPasswordFunc", setPasswordFunc) &&
        LoadFunction(nss, "PORT_Strdup", portStrdup);
    if (!exportsLoaded) {
        FreeLibrary(nss);
        RemoveDllDirectory(dllDirectory);
        std::cerr << "Failed to load function. Error: " << GetWindowsError(GetLastError()) << '\n';
        return 1;
    }

    //g_portStrdup = portStrdup;
    //setPasswordFunc(ReadPrimaryPassword);
    if (nssInit(configPath.c_str()) != 0) {
        std::cerr << "NSS_Init failed. Ensure the profile is closed and its "
            "database matches this Firefox installation.\n";
        FreeLibrary(nss);
        RemoveDllDirectory(dllDirectory);
        return 1;
    }

    int exitCode = 0;
    unsigned int failed = 0;
    SetConsoleOutputCP(CP_UTF8);
    for (size_t i = 0; i < logins.size(); ++i) 
    {
        std::string username;
        std::string password;
        try {
            username = Decrypt(decrypt, freeItem, logins[i]["encryptedUsername"]);
            password = Decrypt(decrypt, freeItem, logins[i]["encryptedPassword"]);
            std::cout << "Login " << (i + 1) << "\n"
                << "  Website: " << logins[i]["hostname"] << "\n"
                << "  Username: " << username << "\n"
                << "  Password: " << password << "\n";
        }
        catch (const std::exception& error) {
            std::cerr << "Login " << (i + 1) << " failed: "
                << error.what() << '\n';
            ++failed;
        }
        if (!username.empty())
            SecureZeroMemory(username.data(), username.size());
        if (!password.empty())
            SecureZeroMemory(password.data(), password.size());
    }
    if (failed != 0) {
        std::cerr << failed << " login(s) could not be decrypted.\n";
        exitCode = 1;
    }

    if (nssShutdown() != 0) {
        std::cerr << "NSS_Shutdown reported a failure.\n";
        exitCode = 1;
    }
    //g_portStrdup = nullptr;
    FreeLibrary(nss);
    RemoveDllDirectory(dllDirectory);
    return exitCode;
}