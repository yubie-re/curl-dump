#pragma once

namespace scanner
{
    // Takes IDA Style Signatures and searches a module for matching bytes, returns first occurence
    void *scan(std::string_view signature, std::string_view name, HMODULE mod);
}