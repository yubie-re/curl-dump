#include "inc.hpp"
#include "scan.hpp"

namespace scanner
{
    struct sig_byte
    {
        uint8_t val;
        bool wild;
    };

    // Turns one char into a hex byte.
    char hex_char_to_byte(char ch)
    {
        if (ch >= '0' && ch <= '9')
            return ch - '0';
        if (ch >= 'A' && ch <= 'F')
            return ch - 'A' + 10;
        if (ch >= 'a' && ch <= 'f')
            return ch - 'a' + 10;
        return 0;
    }

    // Turns hex string into numerical form, ex if uint8_t, it will read the next 2 bytes and turn it into a numerical form
    template <typename T>
    T hex_to_num(const char *hex)
    {
        T value = 0;
        for (size_t i = 0; i < sizeof(T) * 2; ++i)
            value |= hex_char_to_byte(hex[i]) << (8 * sizeof(T) - 4 * (i + 1));
        return value;
    }

    std::vector<sig_byte> ida_to_bytes(std::string_view signature) // Turns IDA Signature to an easier form to search with
    {
        std::vector<sig_byte> bytes;

        for (size_t i = 0; i < signature.length();)
        {
            if (signature[i] == ' ')
            {
                ++i;
            }
            else if (signature[i] == '?')
            {
                bytes.push_back({0x69, true});
                i++;
            }
            else if (isxdigit(signature[i]) && isxdigit(signature[1 + i]))
            {
                bytes.push_back({hex_to_num<uint8_t>(&signature[i]), false});
                i += 2;
            }
            else
            {
                i++;
            }
        }

        return bytes;
    }

    // Get scanning range
    uintptr_t get_img_size(HMODULE mod) 
    {
        auto dos_header = (IMAGE_DOS_HEADER *)mod;
        auto nt_header = (IMAGE_NT_HEADERS *)((uintptr_t)mod + dos_header->e_lfanew);
        return (uintptr_t)nt_header->OptionalHeader.SizeOfImage;
    }

    void *scan(std::string_view signature, std::string_view name, HMODULE mod)
    {
        auto converted_bytes = ida_to_bytes(signature);
        auto img_size = get_img_size(mod);
        auto data = (uint8_t *)mod;

        for (uintptr_t i = 0ull; i < img_size - converted_bytes.size(); i++)
        {
            for (uintptr_t j = 0ull; j < converted_bytes.size(); j++)
            {
                if (!converted_bytes[j].wild && converted_bytes[j].val != data[i + j])
                {
                    break;
                }
                else if (j == converted_bytes.size() - 1)
                {
                    printf("Found %s at %p\n", name.data(), (void *)((uintptr_t)mod + i));
                    return (void *)((uintptr_t)mod + i);
                }
            }
        }
        printf("Failed to find %s\n", name.data());
        return nullptr;
    }
}