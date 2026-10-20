#include "utils.h"
#include "base64.h"

void AppendUtf8(std::string& output, unsigned int codePoint) {
    if (codePoint <= 0x7f) {
        output.push_back(static_cast<char>(codePoint));
    }
    else if (codePoint <= 0x7ff) {
        output.push_back(static_cast<char>(0xc0 | (codePoint >> 6)));
        output.push_back(static_cast<char>(0x80 | (codePoint & 0x3f)));
    }
    else if (codePoint <= 0xffff) {
        output.push_back(static_cast<char>(0xe0 | (codePoint >> 12)));
        output.push_back(static_cast<char>(0x80 | ((codePoint >> 6) & 0x3f)));
        output.push_back(static_cast<char>(0x80 | (codePoint & 0x3f)));
    }
    else {
        output.push_back(static_cast<char>(0xf0 | (codePoint >> 18)));
        output.push_back(static_cast<char>(0x80 | ((codePoint >> 12) & 0x3f)));
        output.push_back(static_cast<char>(0x80 | ((codePoint >> 6) & 0x3f)));
        output.push_back(static_cast<char>(0x80 | (codePoint & 0x3f)));
    }
}

std::vector<unsigned char> DecodeBase64(const std::string& input)
{
    if (input.size() % 4 != 0)
        std::wcout << "Invalid Base64 length in logins.json.";

    size_t padding = 0;
    if (!input.empty() && input.back() == '=')
        ++padding;
    if (input.size() > 1 && input[input.size() - 2] == '=')
        ++padding;
    if (padding > 2)
        std::wcout << "Invalid Base64 padding in logins.json.";

    std::string temp = from_base64(input);

    std::vector<unsigned char> output(temp.begin(), temp.end());

    return output;
}

std::string WideToUtf8(const std::wstring& value) 
{
    if (value.empty())
        return {};
    const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
        value.data(),
        static_cast<int>(value.size()),
        nullptr, 0, nullptr, nullptr);
    if (size <= 0)
        throw std::runtime_error("Could not encode profile path as UTF-8.");
    std::string result(static_cast<size_t>(size), '\0');
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), result.data(),
        size, nullptr, nullptr)) {
        throw std::runtime_error("Could not encode profile path as UTF-8.");
    }
    return result;
}

//template <typename T>
//bool LoadFunction(HMODULE module, const char* name, T& function) 
//{
//    function = reinterpret_cast<T>(GetProcAddress(module, name));
//    if (function)
//        return true;
//    std::cerr << "Missing NSS export: " << name << '\n';
//    return false;
//}

std::string GetWindowsError(DWORD error) 
{
    char* message = nullptr;
    const DWORD size = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<char*>(&message), 0, nullptr);
    std::string result = size && message ? message : "unknown Windows error";
    if (message)
        LocalFree(message);
    return result;
}