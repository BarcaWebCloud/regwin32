/************************************************************************************
      
 *                 Copyright (C) 2021 - 2023, Barca, Inc. 
 
 *    Email: <opensource@barca.com>  GitHub: @BarcaCorporation. 
 *    Project: Speed Run To Clean Your System And Gain More Performance
 
 * This software is licensed as described in the file COPYING, which                    
 * you should have received as part of this distribution. The terms                     
 * are also available at https://BarcaCorporation.github.io/docs/copyright.html.           
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell             
 * copies of the Software, and permit persons to whom the Software is                   
 * furnished to do so, under the terms of the COPYING file.                             
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY            
 * KIND, either express or implied.                                                      
 *
 **************************************************************************************/
#ifndef REGISTRY_CXX
#define REGISTRY_CXX

#include "regwin32.h"
#include <tchar.h>

namespace speedrun {
	namespace Registry {
		
		using namespace speedrun::Registry;
		// deletes a value from a given subkey and root
		bool DeleteRegeditValue(HKEY hKeyRoot, LPCTSTR pszSubKey, LPCTSTR pszValue) {
			HKEY hKey;
			LONG lRes;

			lRes = RegOpenKeyEx(hKeyRoot, pszSubKey, 0, KEY_SET_VALUE, &hKey);

			if (lRes != ERROR_SUCCESS) {
				SetLastError((DWORD)lRes);
				return false;
			}

			lRes = RegDeleteValue(hKey, pszValue);

			RegCloseKey(hKey);

			if (lRes == ERROR_SUCCESS)
				return true;

			SetLastError(lRes);
			return false;
		}

		int CreateRegeditKeyStructure(HKEY hKey, const char *sPath) {
			char sDir[MAX_PATH];

			int iNameSz = (int)strlen(sPath);
			int iCount = 0;
			int iPos = 0;

			for (iPos = 0; iPos < iNameSz; iPos++) {
				if (sPath[iPos] == '\\' || sPath[iPos] == '/') {
					sDir[iPos] = '\0';
					if (CreateRegeditKey(hKey, sDir)) {
						iCount++;
					}
				}

				sDir[iPos] = sPath[iPos];
			}

			sDir[iPos] = '\0';
			if (speedrun::Registry::CreateRegeditKey(hKey, sDir)) {
				iCount++;
			}

			return iCount;
		}

		bool CreateRegeditKey(HKEY hKeyRoot, LPCTSTR pszSubKey) {
			HKEY hKey;
			DWORD dwFunc;
			LONG  lRet;

			SECURITY_DESCRIPTOR SD;
			SECURITY_ATTRIBUTES SA;

			if (!InitializeSecurityDescriptor(&SD, SECURITY_DESCRIPTOR_REVISION))
				return false;

			if (!SetSecurityDescriptorDacl(&SD, true, 0, false))
				return false;

			SA.nLength = sizeof(SA);
			SA.lpSecurityDescriptor = &SD;
			SA.bInheritHandle = false;

			
			lRet = RegCreateKeyEx(
				hKeyRoot,
				pszSubKey,
				0,
				(LPTSTR)NULL,
				REG_OPTION_NON_VOLATILE,
				KEY_WRITE,
				&SA,
				&hKey,
				&dwFunc
				);

			if (lRet == ERROR_SUCCESS) {
				RegCloseKey(hKey);
				hKey = (HKEY)NULL;
				return true;
			}

			SetLastError((DWORD)lRet);
			return false;
		}

		bool DeleteRegeditKey(HKEY hKeyRoot, LPCTSTR pszSubKey) {
			DWORD dwRet = ERROR_SUCCESS;

			if (RegDeleteKey(hKeyRoot, pszSubKey) != ERROR_SUCCESS) {
				HINSTANCE hLibInst = LoadLibrary(_T("shlwapi.dll"));

				if (!hLibInst) {
					//throw ERROR_NO_SHLWAPI_DLL;
				}

				typedef DWORD(__stdcall* SHDELKEYPROC)(HKEY, LPCTSTR);

				#if defined(UNICODE) || defined(_UNICODE)
								SHDELKEYPROC DeleteKeyRecursive = (SHDELKEYPROC)GetProcAddress(hLibInst, "SHDeleteKeyW");
				#else
								SHDELKEYPROC DeleteKeyRecursive = (SHDELKEYPROC)GetProcAddress(hLibInst, "SHDeleteKeyA");
				#endif

				if (!DeleteKeyRecursive) {
					FreeLibrary(hLibInst);
					return false;
				}

				dwRet = DeleteKeyRecursive(hKeyRoot, pszSubKey);

				FreeLibrary(hLibInst);
			}

			if (dwRet == ERROR_SUCCESS)
				return true;

			SetLastError(dwRet);
			return false;
		}

		bool GetBinaryRegeditValue(HKEY hKeyRoot, LPCTSTR pszSubKey, LPCTSTR pszValue, PVOID pBuffer, DWORD& rdwSize) {
			HKEY  hKey;
			DWORD dwType = REG_BINARY;
			DWORD dwSize = rdwSize;
			LONG lRes = 0;

			lRes = RegOpenKeyEx(hKeyRoot, pszSubKey, 0, KEY_READ, &hKey);

			if (lRes != ERROR_SUCCESS) {
				SetLastError((DWORD)lRes);
				return false;
			}

			lRes = RegQueryValueEx(hKey, pszValue, 0, &dwType, (LPBYTE)pBuffer, &dwSize);

			rdwSize = dwSize;
			RegCloseKey(hKey);

			if (lRes != ERROR_SUCCESS)	{
				SetLastError(lRes);
				return false;
			}

			if (dwType != REG_BINARY) {
				//throw ERROR_WRONG_TYPE;
			}

			return true;
		}

		bool GetDWORDRegeditValue(HKEY hKeyRoot, LPCTSTR pszSubKey, LPCTSTR pszValue, unsigned __int64 &u64Buff) {
			HKEY hKey;
			DWORD dwType = REG_QWORD;
			DWORD dwSize = sizeof(u64Buff);
			LONG  lRes;

			u64Buff = 0;

			lRes = RegOpenKeyEx(hKeyRoot, pszSubKey, 0, KEY_READ, &hKey);

			if (lRes != ERROR_SUCCESS) {
				SetLastError(lRes);
				return false;
			}

			lRes = RegQueryValueEx(hKey, pszValue, 0, &dwType, (LPBYTE)&u64Buff, &dwSize);

			RegCloseKey(hKey);

			if (dwType != REG_QWORD)
				//throw ERROR_WRONG_TYPE;

				if (lRes != ERROR_SUCCESS) {
					SetLastError(lRes);
					return false;
				}

			return true;
		}

		bool GetDWORDRegeditValue(HKEY hKeyRoot, LPCTSTR pszSubKey, LPCTSTR pszValue, unsigned long &ulBuff) {
			HKEY hKey;
			DWORD dwType = REG_DWORD;
			DWORD dwSize = sizeof(ulBuff);
			LONG  lRes;

			ulBuff = 0;

			lRes = RegOpenKeyEx(hKeyRoot, pszSubKey, 0, KEY_READ, &hKey);

			if (lRes != ERROR_SUCCESS) {
				SetLastError(lRes);
				return false;
			}

			lRes = RegQueryValueEx(hKey, pszValue, 0, &dwType, (LPBYTE)&ulBuff, &dwSize);

			RegCloseKey(hKey);

			if (dwType != REG_DWORD)
				//throw ERROR_WRONG_TYPE;

				if (lRes != ERROR_SUCCESS) {
					SetLastError(lRes);
					return false;
				}

			return true;
		}

		bool GetStringRegeditValue(HKEY hKeyRoot, LPCTSTR pszSubKey, LPCTSTR pszValue, LPTSTR pszBuffer, DWORD& rdwSize) {
			HKEY  hKey;
			LONG  lRes;
			DWORD dwType = KEY_ALL_ACCESS;

			lRes = RegOpenKeyEx(hKeyRoot, pszSubKey, 0, KEY_READ, &hKey);
			if (lRes != ERROR_SUCCESS) {
				RegCloseKey(hKey);
				SetLastError(lRes);
				return false;
			}

			lRes = RegQueryValueEx(hKey, pszValue, NULL, &dwType, (unsigned char*)pszBuffer, &rdwSize);
			if (lRes != ERROR_SUCCESS) {
				RegCloseKey(hKey);
				SetLastError(lRes);
				return false;
			}

			lRes = RegCloseKey(hKey);
			if (lRes != ERROR_SUCCESS) {
				RegCloseKey(hKey);
				SetLastError(lRes);
				return false;
			}

			return true;
		}

		bool SetBinaryRegeditValue(HKEY hKeyRoot, LPCTSTR pszSubKey, LPCTSTR pszValue, PVOID pData, DWORD dwSize) {
			HKEY hKey;
			LONG lRes = 0;

			lRes = RegOpenKeyEx(hKeyRoot, pszSubKey, 0, KEY_WRITE, &hKey);

			if (lRes != ERROR_SUCCESS) {
				SetLastError(lRes);
				return false;
			}

			lRes = RegSetValueEx(hKey, pszValue, 0, REG_BINARY, (unsigned char*)pData, dwSize);

			RegCloseKey(hKey);

			if (lRes != ERROR_SUCCESS) {
				SetLastError(lRes);
				return false;
			}

			return true;
		}

		bool SetDWORDRegeditValue(HKEY hKeyRoot, LPCTSTR pszSubKey, LPCTSTR pszValue, unsigned long ulValue) {
			HKEY hKey;
			LONG lRes;

			lRes = RegOpenKeyEx(hKeyRoot, pszSubKey, 0, KEY_WRITE, &hKey);

			if (lRes != ERROR_SUCCESS) {
				SetLastError(lRes);
				return false;
			}

			lRes = RegSetValueEx(hKey, pszValue, 0, REG_DWORD, (unsigned char*)&ulValue, sizeof(ulValue));

			RegCloseKey(hKey);

			if (lRes != ERROR_SUCCESS) {
				SetLastError(lRes);
				return false;
			}

			return true;
		}

		bool SetDWORDRegeditValue(HKEY hKeyRoot, LPCTSTR pszSubKey, LPCTSTR pszValue, unsigned __int64 u64Value) {
			HKEY hKey;
			LONG lRes;

			lRes = RegOpenKeyEx(hKeyRoot, pszSubKey, 0, KEY_WRITE, &hKey);

			if (lRes != ERROR_SUCCESS) {
				SetLastError(lRes);
				return false;
			}

			lRes = RegSetValueEx(hKey, pszValue, 0, REG_QWORD, (LPBYTE)&u64Value, sizeof(u64Value));

			RegCloseKey(hKey);

			if (lRes != ERROR_SUCCESS) {
				SetLastError(lRes);
				return false;
			}

			return true;
		}

		bool SetStringRegeditValue(HKEY hKeyRoot, LPCTSTR pszSubKey, LPCTSTR pszValue, LPCTSTR pszString) {
			HKEY  hKey;
			LONG  lRes;
			DWORD dwSize = lstrlen(pszString) * sizeof(TCHAR);

			lRes = RegOpenKeyEx(hKeyRoot, pszSubKey, 0, KEY_WRITE, &hKey);

			if (lRes != ERROR_SUCCESS){
				SetLastError(lRes);
				return false;
			}
			lRes = RegSetValueEx(hKey, pszValue, 0, REG_SZ, (unsigned char*)pszString, dwSize);

			RegCloseKey(hKey);

			if (lRes != ERROR_SUCCESS) {
				SetLastError(lRes);
				return false;
			}

			return true;
		}

		bool SetBOOLRegeditValue(HKEY hKeyRoot, LPCTSTR pszSubKey, LPCTSTR pszValue, bool bVal) {
			DWORD dwVal = 0;
			if (bVal) {
				dwVal = 1;
			}

			return SetDWORDRegeditValue(hKeyRoot, pszSubKey, pszValue, dwVal);
		}

		bool GetBOOLRegeditValue(HKEY hKeyRoot, LPCTSTR pszSubKey, LPCTSTR pszValue) {
			DWORD dwVal = 0;

			if (GetDWORDRegeditValue(hKeyRoot, pszSubKey, pszValue, dwVal)) {
				return (dwVal > 0);
			}
			return false;
		}
		
	}
} 
#endif