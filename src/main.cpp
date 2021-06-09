#include "inc.hpp"
#include "scan.hpp"

bool g_hooked_write = false;
void *g_curl_address = nullptr;
void *g_write_func_address = nullptr;

// Some executables which have anti-VirtualProtect (ex. VMP/Themida packed) stuff won't hook as simple as this, you will need to disable the minhook vp check and find another way to get write priveleges to the memory
// It will alert if it does fail due to this, generally with MH_ERROR_MEMORY_PROTECT or something similar
// I might release a bypass for this later, it just would impact the cleanliness of this source

void hook_func(void **orig, void *address, void *hook)
{
    auto res = MH_CreateHook(address, hook, orig);
    if (res != MH_OK)
    {
        printf("CreateHook failed: %s\n", MH_StatusToString(res));
    }
    res = MH_EnableHook(address);
    if (res != MH_OK)
    {
        printf("EnableHook failed: %s\n", MH_StatusToString(res));
    }
}

void unhook_func(void *address)
{
    auto res = MH_DisableHook(address);
    if (res != MH_OK)
    {
        printf("DisableHook failed: %s\n", MH_StatusToString(res));
    }
}

size_t (*o_write_callback)(char *ptr, size_t size, size_t nmemb, void *userdata);


/*

To modify responses:

if(modify_this)
{
    auto resp = "New response!";
    o_write_callback((char*)resp, 1, strlen(resp), userdata);
    return size * nmemb;
}

*/

size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    std::string out(static_cast<const char *>(ptr), size * nmemb);
    printf("Write Callback %s", out.c_str());
    printf("\nEND\n");
    return o_write_callback(ptr, size, nmemb, userdata);
}

uint32_t (*o_curl_easy_setopt)(void *handle, uint32_t option, void *parameter);

uint32_t curl_easy_setopt(void *handle, uint32_t option, void *parameter)
{
    if (option == 10002)
    {
        printf("URL: %d %s\n", option, (char *)parameter);
    }
    else if (option == 10015)
    {
        printf("Post Fields: %d %s\n", option, (char *)parameter);
    }
    else if (option == 20011)
    {
        if (!g_hooked_write)
        {
            printf("Write Function: %d %p, Hooking...\n", option, (void *)parameter);
            hook_func((void **)&o_write_callback, parameter, write_callback);
            g_write_func_address = parameter;
            g_hooked_write = true;
        }
        else
        {
            printf("Write Function: %d %p\n", option, (void *)parameter);
        }
    }
    else if (option == 10018)
    {
        printf("User Agent: %d %s\n", option, (char *)parameter);
    }
    else if (option == 10036)
    {
        printf("Custom Request: %d %s\n", option, (char *)parameter);
    }
    else if (option == 10103)
    {
        printf("Private Data: %d %p\n", option, parameter);
    }
    else
    {
        // https://gist.github.com/jseidl/3218673 Refer here if needed
#if _WIN64
        printf("Unknown: %d %llx\n", option, (uint64_t)parameter);
#else
        printf("Unknown: %d %x\n", option, (uint32_t)parameter);
#endif
    }
    return o_curl_easy_setopt(handle, option, parameter);
}

void hook()
{
    MH_Initialize();

#if _WIN64
    g_curl_address = scanner::scan("89 54 24 10 4C 89 44 24 ? 4C 89 4C 24 ? 48 83 EC 28 48 85 C9 75 08 8D 41 2B 48 83 C4 28 C3 4C 8D 44 24 ? E8 ? ? ? ? 48 83 C4 28 C3", "curl_easy_setopt", GetModuleHandleA(nullptr));
#else
    g_curl_address = scanner::scan("8B 44 24 04 85 C0 75 06 B8 ? ? ? ? C3 8D 4C 24 0C 51 FF 74 24 0C 50 E8 ? ? ? ? 83 C4 0C C3", "curl_easy_setopt", GetModuleHandleA(nullptr));
#endif

    //g_curl_address = (void*)((uintptr_t)GetModuleHandleA(nullptr) + 0xFFFFFF); // Replace offset if you want to hardcode it
    if (g_curl_address)
        hook_func((void **)&o_curl_easy_setopt, g_curl_address, curl_easy_setopt);
}

void unhook()
{
    if (g_curl_address)
        unhook_func(g_curl_address);
    if (g_write_func_address)
        unhook_func(g_write_func_address);
}

DWORD WINAPI main_thread(PVOID module)
{
    AllocConsole();
    freopen("CONOUT$", "w", stdout);
    hook();
    while (!GetAsyncKeyState(VK_DELETE))
    {
        std::this_thread::yield();
    }
    unhook();
    fclose(stdout);
    FreeConsole();
    FreeLibraryAndExitThread((HMODULE)module, 0);
    return 1;
}

// Entrypoint
BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        CreateThread(nullptr, 0, &main_thread, (void *)module, 0, nullptr);
    }
    return TRUE;
}