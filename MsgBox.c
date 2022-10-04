#include <stdio.h>
#include <windows.h>

// https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxw

int main(void)
{
	MessageBoxW(NULL, L"Body\n\nBody\n\nWrite", L"Title", MB_ICONEXCLAMATION);
	return 0;
}