#include <windows.h>
#include <chrono>
#include <vector>
#include <algorithm>
#include <iostream>

struct ClickEvent {
    std::chrono::steady_clock::time_point time;
    int x;
    int y;
};

std::vector<ClickEvent> clickEvents;
HHOOK mouseHook;

void InitializeRawInput(HWND hwnd);
void ProcessRawInput(LPARAM lParam);
void TrackMouseClick(int x, int y);
bool IsSuspiciousClickPattern();
LRESULT CALLBACK LowLevelMouseProc(int nCode, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
void SetMouseHook();
void RemoveMouseHook();

int main() {
    const wchar_t CLASS_NAME[] = L"Sample Window Class";

    WNDCLASS wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = CLASS_NAME;

    RegisterClass(&wc);

    HWND hwnd = CreateWindowEx(
        0,
        CLASS_NAME,
        L"Mouse Input Monitor",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
        NULL,
        NULL,
        GetModuleHandle(NULL),
        NULL
    );

    if (hwnd == NULL) {
        std::cerr << "Failed to create window." << std::endl;
        return 0;
    }

    InitializeRawInput(hwnd);
    SetMouseHook();

    ShowWindow(hwnd, SW_HIDE); // Hide the window

    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    RemoveMouseHook();
    return 0;
}

void InitializeRawInput(HWND hwnd) {
    RAWINPUTDEVICE rid;
    rid.usUsagePage = 0x01;
    rid.usUsage = 0x02;
    rid.dwFlags = RIDEV_INPUTSINK;
    rid.hwndTarget = hwnd;

    if (!RegisterRawInputDevices(&rid, 1, sizeof(rid))) {
        std::cerr << "Failed to register raw input devices." << std::endl;
    }
}

void ProcessRawInput(LPARAM lParam) {
    UINT dwSize;
    GetRawInputData((HRAWINPUT)lParam, RID_INPUT, NULL, &dwSize, sizeof(RAWINPUTHEADER));
    LPBYTE lpb = new BYTE[dwSize];

    if (lpb == NULL) {
        return;
    }

    if (GetRawInputData((HRAWINPUT)lParam, RID_INPUT, lpb, &dwSize, sizeof(RAWINPUTHEADER)) != dwSize) {
        std::cerr << "GetRawInputData does not return correct size." << std::endl;
    }

    RAWINPUT* raw = (RAWINPUT*)lpb;
    if (raw->header.dwType == RIM_TYPEMOUSE) {
        // Process mouse data
        // raw->data.mouse contains the mouse input data
        if (raw->data.mouse.usButtonFlags & RI_MOUSE_LEFT_BUTTON_DOWN) {
            TrackMouseClick(raw->data.mouse.lLastX, raw->data.mouse.lLastY);
            if (IsSuspiciousClickPattern()) {
                std::cout << "Suspicious mouse click pattern detected!" << std::endl;
            }
        }
    }

    delete[] lpb;
}

void TrackMouseClick(int x, int y) {
    auto now = std::chrono::steady_clock::now();
    clickEvents.push_back({ now, x, y });

    // Optional: Remove old events to keep the list manageable
    auto cutoff = now - std::chrono::seconds(10);
    clickEvents.erase(
        std::remove_if(clickEvents.begin(), clickEvents.end(), [cutoff](const ClickEvent& e) {
            return e.time < cutoff;
            }), clickEvents.end());
}

bool IsSuspiciousClickPattern() {
    if (clickEvents.size() < 2) return false;

    for (size_t i = 1; i < clickEvents.size(); ++i) {
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(clickEvents[i].time - clickEvents[i - 1].time).count();
        if (duration < 20) { // Threshold in milliseconds
            return true;
        }
    }

    return false;
}

LRESULT CALLBACK LowLevelMouseProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION) {
        MSLLHOOKSTRUCT* pMouseStruct = (MSLLHOOKSTRUCT*)lParam;
        if (pMouseStruct != nullptr) {
            // Check for flags that indicate synthetic events
            if (pMouseStruct->flags & LLMHF_INJECTED || pMouseStruct->flags & LLMHF_LOWER_IL_INJECTED) {
                std::cout << "Emulated mouse input detected!" << std::endl;
                return 1; // Block the event
            }
        }
    }

    return CallNextHookEx(mouseHook, nCode, wParam, lParam);
}

void SetMouseHook() {
    mouseHook = SetWindowsHookEx(WH_MOUSE_LL, LowLevelMouseProc, NULL, 0);
    if (mouseHook == NULL) {
        std::cerr << "Failed to set mouse hook." << std::endl;
    }
}

void RemoveMouseHook() {
    if (mouseHook != NULL) {
        UnhookWindowsHookEx(mouseHook);
    }
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_INPUT:
        ProcessRawInput(lParam);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
        // Handle other messages
    }

    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}
