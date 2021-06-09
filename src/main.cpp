#include "inc.hpp"
#include "scan.hpp"

bool g_hooked_write = false;
void* curl_address = nullptr;


void hook_func(void** orig, void* address, void* hook)
{
    //MH_CreateHook(address, hook, orig);
    //MH_EnableHook(address);
}

void unhook_func(void** orig, void* address, void* hook)
{
    //MH_CreateHook(address, hook, orig);
    //MH_EnableHook(address);
}

size_t(*o_write_callback)(char* ptr, size_t size, size_t nmemb, void* userdata);

size_t write_callback(char* ptr, size_t size, size_t nmemb, void* userdata)
{
    std::string out(static_cast<const char*>(ptr), size * nmemb);
    printf("Write Callback %s", out.c_str());
    printf("\nEND\n");
    return o_write_callback(ptr, size, nmemb, userdata);
}

uint32_t(*o_curl_easy_setopt)(void* handle, uint32_t option, void* parameter);

uint32_t curl_easy_setopt(void* handle, uint32_t option, void* parameter)
{
    if (option == 10002)
    {
        printf("URL %p %d %s\n", handle, option, (char*)parameter);
    }
    else if (option == 10015)
    {
        printf("PF %p %d %s\n", handle, option, (char*)parameter);
    }
    else if (option == 20011)
    {
        if (!g_hooked_write)
        {
            printf("WF %p %d %p, Hooking...\n", handle, option, (void*)parameter);
            hook_func((void**)&o_write_callback, parameter, write_callback);
            g_hooked_write = true;
        }
        else
        {
            printf("WF %p %d %p\n", handle, option, (void*)parameter);
        }
    }
    else if (option == 10018)
    {
        printf("UA %p %d %s\n", handle, option, (char*)parameter);
    }
    else if (option == 10036)
    {
        printf("CR %p %d %s\n", handle, option, (char*)parameter);
    }
    else if (option == 10103)
    {
        printf("PRIVDATA %p %d %p\n", handle, option, parameter);
    }
    else
    {
        printf("%p %d %d\n", handle, option, (uintptr_t)parameter);
    }
    return o_curl_easy_setopt(handle, option, parameter);
}

void hook()
{

}

void unhook()
{

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
    return 1;
}

// Entrypoint
BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        CreateThread(nullptr, 0, &main_thread, nullptr, 0, nullptr);
    }
    return TRUE;
}