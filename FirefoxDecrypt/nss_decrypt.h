#pragma once
#include "utils.h"
#include <filesystem>

std::string GetNssConfigPath(const std::filesystem::path& profile);
std::string Decrypt(PK11SDRDecryptFn decrypt, SECItemZfreeItemFn freeItem, const std::string& encoded);