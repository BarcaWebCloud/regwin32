
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
#ifndef REGISTRY
#define REGISTRY

#include <wtypes.h>

namespace speedrun {
	namespace Registry {
		
		int CreateRegeditKeyStructure(HKEY hKey, const char *sPath);
		bool CreateRegeditKey(HKEY hKeyRoot, LPCTSTR pszSubKey);
		bool DeleteRegeditKey(HKEY hKeyRoot, LPCTSTR pszSubKey);
		bool DeleteRegeditValue(HKEY hKeyRoot, LPCTSTR pszSubKey, LPCTSTR pszValue);
		bool GetBinaryRegeditValue(HKEY hKeyRoot, LPCTSTR pszSubKey, LPCTSTR pszValue, PVOID pBuffer, DWORD& rdwSize);
		bool GetBOOLRegeditValue(HKEY hKeyRoot, LPCTSTR pszSubKey, LPCTSTR pszValue);
		bool GetDWORDRegeditValue(HKEY hKeyRoot, LPCTSTR pszSubKey, LPCTSTR pszValue, unsigned long &ulBuff);
		bool GetDWORDRegeditValue(HKEY hKeyRoot, LPCTSTR pszSubKey, LPCTSTR pszValue, unsigned __int64 &u64Buff);
		bool GetStringRegeditValue(HKEY hKeyRoot, LPCTSTR pszSubKey, LPCTSTR pszValue, LPTSTR pszBuffer, DWORD& rdwSize);
		bool SetBinaryRegeditValue(HKEY hKeyRoot, LPCTSTR pszSubKey, LPCTSTR pszValue, PVOID pData, DWORD dwSize);
		bool SetBOOLRegeditValue(HKEY hKeyRoot, LPCTSTR pszSubKey, LPCTSTR pszValue, bool bVal);
		bool SetDWORDRegeditValue(HKEY hKeyRoot, LPCTSTR pszSubKey, LPCTSTR pszValue, unsigned long ulValue);
		bool SetDWORDRegeditValue(HKEY hKeyRoot, LPCTSTR pszSubKey, LPCTSTR pszValue, unsigned __int64 u64Buff);
		bool SetStringRegeditValue(HKEY hKeyRoot, LPCTSTR pszSubKey, LPCTSTR pszValue, LPCTSTR pszString);	
	}
}
#endif