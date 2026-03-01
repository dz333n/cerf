/* Win32 thunks: system info, time, sync, locale, registry, resources, misc */
#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include "win32_thunks.h"
#include <cstdio>
#include <algorithm>
#include <commctrl.h>
#include <vector>

bool Win32Thunks::ExecuteSystemThunk(const std::string& func, uint32_t* regs, EmulatedMemory& mem) {
    /* Error handling */
    if (func == "GetLastError") {
        regs[0] = GetLastError();
        return true;
    }
    if (func == "SetLastError") {
        SetLastError(regs[0]);
        return true;
    }
    if (func == "RaiseException") {
        printf("[THUNK] RaiseException(0x%08X) - ignoring\n", regs[0]);
        return true;
    }

    /* System info */
    if (func == "GetSystemMetrics") {
        int idx = (int)regs[0];
        if (idx == SM_CXSCREEN || idx == SM_CYSCREEN) {
            RECT work_area;
            SystemParametersInfoW(SPI_GETWORKAREA, 0, &work_area, 0);
            regs[0] = (idx == SM_CXSCREEN)
                ? (uint32_t)(work_area.right - work_area.left)
                : (uint32_t)(work_area.bottom - work_area.top);
            return true;
        }
        regs[0] = GetSystemMetrics(idx);
        return true;
    }
    if (func == "GetSysColor") {
        regs[0] = GetSysColor(regs[0]);
        return true;
    }
    if (func == "GetSysColorBrush") {
        regs[0] = (uint32_t)(uintptr_t)GetSysColorBrush(regs[0]);
        return true;
    }
    if (func == "GetTickCount") {
        regs[0] = GetTickCount();
        return true;
    }
    if (func == "GetSystemInfo") {
        if (regs[0]) {
            SYSTEM_INFO si;
            GetSystemInfo(&si);
            mem.Write32(regs[0] + 0, 0);    /* wProcessorArchitecture = ARM */
            mem.Write32(regs[0] + 4, si.dwPageSize);
            mem.Write32(regs[0] + 8, 0x10000);
            mem.Write32(regs[0] + 12, 0x7FFFFFFF);
            mem.Write32(regs[0] + 20, 1);
            mem.Write32(regs[0] + 24, 0x4);
        }
        return true;
    }

    /* Time functions */
    if (func == "Sleep") {
        Sleep(regs[0]);
        return true;
    }
    if (func == "GetLocalTime" || func == "GetSystemTime") {
        SYSTEMTIME st;
        if (func == "GetLocalTime") GetLocalTime(&st);
        else GetSystemTime(&st);
        if (regs[0]) {
            mem.Write16(regs[0] + 0, st.wYear);
            mem.Write16(regs[0] + 2, st.wMonth);
            mem.Write16(regs[0] + 4, st.wDayOfWeek);
            mem.Write16(regs[0] + 6, st.wDay);
            mem.Write16(regs[0] + 8, st.wHour);
            mem.Write16(regs[0] + 10, st.wMinute);
            mem.Write16(regs[0] + 12, st.wSecond);
            mem.Write16(regs[0] + 14, st.wMilliseconds);
        }
        return true;
    }

    /* Sync */
    if (func == "InitializeCriticalSection" || func == "DeleteCriticalSection" ||
        func == "EnterCriticalSection" || func == "LeaveCriticalSection") {
        return true;
    }
    if (func == "CreateEventW") {
        regs[0] = (uint32_t)(uintptr_t)CreateEventW(NULL, regs[1], regs[2], NULL);
        return true;
    }
    if (func == "WaitForSingleObject") {
        regs[0] = WaitForSingleObject((HANDLE)(intptr_t)(int32_t)regs[0], regs[1]);
        return true;
    }
    if (func == "CloseHandle") {
        uint32_t fake = regs[0];
        HANDLE h = UnwrapHandle(fake);
        regs[0] = CloseHandle(h);
        RemoveHandle(fake);
        return true;
    }
    if (func == "CreateMutexW") {
        regs[0] = (uint32_t)(uintptr_t)CreateMutexW(NULL, regs[1], NULL);
        return true;
    }
    if (func == "ReleaseMutex") {
        regs[0] = ReleaseMutex((HANDLE)(intptr_t)(int32_t)regs[0]);
        return true;
    }

    /* TLS */
    if (func == "TlsGetValue" || func == "TlsSetValue" || func == "TlsCall") {
        printf("[STUB] %s -> 0\n", func.c_str());
        regs[0] = 0;
        return true;
    }

    /* Locale */
    if (func == "GetLocaleInfoW") {
        wchar_t buf[256] = {};
        uint32_t maxlen = regs[3];
        if (maxlen > 256) maxlen = 256;
        int ret = GetLocaleInfoW(regs[0], regs[1], buf, (int)maxlen);
        uint32_t dst = regs[2];
        for (int i = 0; i < ret; i++) mem.Write16(dst + i * 2, buf[i]);
        regs[0] = ret;
        return true;
    }
    if (func == "GetSystemDefaultLangID") {
        regs[0] = GetSystemDefaultLangID();
        return true;
    }
    if (func == "GetUserDefaultLCID") {
        regs[0] = GetUserDefaultLCID();
        return true;
    }
    if (func == "GetSystemDefaultLCID") {
        regs[0] = GetSystemDefaultLCID();
        return true;
    }
    if (func == "ConvertDefaultLocale") {
        regs[0] = ConvertDefaultLocale(regs[0]);
        return true;
    }
    if (func == "GetACP") {
        regs[0] = GetACP();
        return true;
    }
    if (func == "GetOEMCP") {
        regs[0] = GetOEMCP();
        return true;
    }
    if (func == "GetCPInfo") {
        printf("[STUB] GetCPInfo -> 0\n");
        regs[0] = 0;
        return true;
    }
    if (func == "LCMapStringW" || func == "GetTimeFormatW" || func == "GetDateFormatW") {
        printf("[STUB] %s -> 0\n", func.c_str());
        regs[0] = 0;
        return true;
    }

    /* ---- Emulated Registry ---- */
    if (func == "RegOpenKeyExW") {
        LoadRegistry();
        /* R0=hKey, R1=lpSubKey, R2=ulOptions, R3=samDesired, stack[0]=phkResult */
        uint32_t parent_hkey = regs[0];
        std::wstring subkey;
        if (regs[1]) subkey = ReadWStringFromEmu(mem, regs[1]);
        uint32_t phkResult = ReadStackArg(regs, mem, 0);

        std::wstring full_path = ResolveHKey(parent_hkey, subkey);
        auto it = registry.find(full_path);
        if (it == registry.end()) {
            printf("[REG] RegOpenKeyExW('%ls') -> NOT FOUND\n", full_path.c_str());
            regs[0] = ERROR_FILE_NOT_FOUND;
            return true;
        }

        uint32_t fake = next_fake_hkey++;
        hkey_map[fake] = full_path;
        if (phkResult) mem.Write32(phkResult, fake);
        printf("[REG] RegOpenKeyExW('%ls') -> 0x%08X\n", full_path.c_str(), fake);
        regs[0] = ERROR_SUCCESS;
        return true;
    }
    if (func == "RegCreateKeyExW") {
        LoadRegistry();
        /* R0=hKey, R1=lpSubKey, R2=reserved, R3=lpClass,
           stack[0]=dwOptions, stack[1]=samDesired, stack[2]=lpSecurityAttribs,
           stack[3]=phkResult, stack[4]=lpdwDisposition */
        uint32_t parent_hkey = regs[0];
        std::wstring subkey;
        if (regs[1]) subkey = ReadWStringFromEmu(mem, regs[1]);
        uint32_t phkResult = ReadStackArg(regs, mem, 3);
        uint32_t pDisposition = ReadStackArg(regs, mem, 4);

        std::wstring full_path = ResolveHKey(parent_hkey, subkey);
        bool existed = registry.find(full_path) != registry.end();
        registry[full_path]; /* create if not exists */
        EnsureParentKeys(full_path);

        uint32_t fake = next_fake_hkey++;
        hkey_map[fake] = full_path;
        if (phkResult) mem.Write32(phkResult, fake);
        if (pDisposition) mem.Write32(pDisposition, existed ? 2 : 1); /* REG_OPENED_EXISTING_KEY / REG_CREATED_NEW_KEY */
        printf("[REG] RegCreateKeyExW('%ls') -> 0x%08X (%s)\n",
               full_path.c_str(), fake, existed ? "opened" : "created");
        regs[0] = ERROR_SUCCESS;
        return true;
    }
    if (func == "RegCloseKey") {
        /* R0=hKey */
        hkey_map.erase(regs[0]);
        SaveRegistry();
        regs[0] = ERROR_SUCCESS;
        return true;
    }
    if (func == "RegQueryValueExW") {
        LoadRegistry();
        /* R0=hKey, R1=lpValueName, R2=lpReserved, R3=lpType,
           stack[0]=lpData, stack[1]=lpcbData */
        uint32_t hkey = regs[0];
        std::wstring value_name;
        if (regs[1]) value_name = ReadWStringFromEmu(mem, regs[1]);
        uint32_t pType = regs[3];
        uint32_t pData = ReadStackArg(regs, mem, 0);
        uint32_t pcbData = ReadStackArg(regs, mem, 1);

        auto kit = hkey_map.find(hkey);
        if (kit == hkey_map.end()) {
            regs[0] = ERROR_INVALID_HANDLE;
            return true;
        }
        auto rit = registry.find(kit->second);
        if (rit == registry.end()) {
            regs[0] = ERROR_FILE_NOT_FOUND;
            return true;
        }
        auto vit = rit->second.values.find(value_name);
        if (vit == rit->second.values.end()) {
            regs[0] = ERROR_FILE_NOT_FOUND;
            return true;
        }

        const RegValue& val = vit->second;
        if (pType) mem.Write32(pType, val.type);

        uint32_t data_size = (uint32_t)val.data.size();
        if (pcbData) {
            uint32_t buf_size = mem.Read32(pcbData);
            mem.Write32(pcbData, data_size);
            if (pData && buf_size >= data_size) {
                for (uint32_t i = 0; i < data_size; i++)
                    mem.Write8(pData + i, val.data[i]);
            } else if (pData) {
                regs[0] = ERROR_MORE_DATA;
                return true;
            }
        }
        printf("[REG] RegQueryValueExW('%ls', '%ls') -> %u bytes\n",
               kit->second.c_str(), value_name.c_str(), data_size);
        regs[0] = ERROR_SUCCESS;
        return true;
    }
    if (func == "RegSetValueExW") {
        LoadRegistry();
        /* R0=hKey, R1=lpValueName, R2=reserved, R3=dwType,
           stack[0]=lpData, stack[1]=cbData */
        uint32_t hkey = regs[0];
        std::wstring value_name;
        if (regs[1]) value_name = ReadWStringFromEmu(mem, regs[1]);
        uint32_t type = regs[3];
        uint32_t pData = ReadStackArg(regs, mem, 0);
        uint32_t cbData = ReadStackArg(regs, mem, 1);

        auto kit = hkey_map.find(hkey);
        if (kit == hkey_map.end()) {
            regs[0] = ERROR_INVALID_HANDLE;
            return true;
        }

        RegValue val;
        val.type = type;
        if (cbData > 0 && cbData < 0x10000) {
            val.data.resize(cbData);
            for (uint32_t i = 0; i < cbData; i++)
                val.data[i] = mem.Read8(pData + i);
        }

        registry[kit->second].values[value_name] = val;
        printf("[REG] RegSetValueExW('%ls', '%ls') type=%u size=%u\n",
               kit->second.c_str(), value_name.c_str(), type, cbData);
        regs[0] = ERROR_SUCCESS;
        return true;
    }
    if (func == "RegDeleteKeyW") {
        /* R0=hKey, R1=lpSubKey */
        uint32_t hkey = regs[0];
        std::wstring subkey;
        if (regs[1]) subkey = ReadWStringFromEmu(mem, regs[1]);
        auto kit = hkey_map.find(hkey);
        std::wstring path = (kit != hkey_map.end()) ? kit->second + L"\\" + subkey : subkey;
        registry.erase(path);
        printf("[REG] RegDeleteKeyW('%ls')\n", path.c_str());
        regs[0] = ERROR_SUCCESS;
        return true;
    }
    if (func == "RegDeleteValueW") {
        /* R0=hKey, R1=lpValueName */
        uint32_t hkey = regs[0];
        std::wstring value_name;
        if (regs[1]) value_name = ReadWStringFromEmu(mem, regs[1]);
        auto kit = hkey_map.find(hkey);
        if (kit != hkey_map.end()) {
            auto rit = registry.find(kit->second);
            if (rit != registry.end()) rit->second.values.erase(value_name);
        }
        regs[0] = ERROR_SUCCESS;
        return true;
    }
    if (func == "RegEnumValueW") {
        LoadRegistry();
        /* R0=hKey, R1=dwIndex, R2=lpValueName, R3=lpcchValueName,
           stack[0]=lpReserved, stack[1]=lpType, stack[2]=lpData, stack[3]=lpcbData */
        uint32_t hkey = regs[0];
        uint32_t index = regs[1];
        uint32_t pName = regs[2];
        uint32_t pcchName = regs[3];
        uint32_t pType = ReadStackArg(regs, mem, 1);
        uint32_t pData = ReadStackArg(regs, mem, 2);
        uint32_t pcbData = ReadStackArg(regs, mem, 3);

        auto kit = hkey_map.find(hkey);
        if (kit == hkey_map.end()) { regs[0] = ERROR_INVALID_HANDLE; return true; }
        auto rit = registry.find(kit->second);
        if (rit == registry.end() || index >= rit->second.values.size()) {
            regs[0] = ERROR_NO_MORE_ITEMS;
            return true;
        }
        auto vit = rit->second.values.begin();
        std::advance(vit, index);

        /* Write value name */
        if (pName && pcchName) {
            uint32_t maxch = mem.Read32(pcchName);
            for (uint32_t i = 0; i < vit->first.size() && i < maxch; i++)
                mem.Write16(pName + i * 2, vit->first[i]);
            mem.Write16(pName + (uint32_t)vit->first.size() * 2, 0);
            mem.Write32(pcchName, (uint32_t)vit->first.size());
        }
        if (pType) mem.Write32(pType, vit->second.type);
        if (pData && pcbData) {
            uint32_t buf_size = mem.Read32(pcbData);
            uint32_t data_size = (uint32_t)vit->second.data.size();
            mem.Write32(pcbData, data_size);
            for (uint32_t i = 0; i < data_size && i < buf_size; i++)
                mem.Write8(pData + i, vit->second.data[i]);
        }
        regs[0] = ERROR_SUCCESS;
        return true;
    }
    if (func == "RegEnumKeyExW") {
        LoadRegistry();
        /* R0=hKey, R1=dwIndex, R2=lpName, R3=lpcchName,
           stack[0]=lpReserved, stack[1]=lpClass, stack[2]=lpcchClass, stack[3]=lpftLastWriteTime */
        uint32_t hkey = regs[0];
        uint32_t index = regs[1];
        uint32_t pName = regs[2];
        uint32_t pcchName = regs[3];

        auto kit = hkey_map.find(hkey);
        if (kit == hkey_map.end()) { regs[0] = ERROR_INVALID_HANDLE; return true; }
        auto rit = registry.find(kit->second);
        if (rit == registry.end() || index >= rit->second.subkeys.size()) {
            regs[0] = ERROR_NO_MORE_ITEMS;
            return true;
        }
        auto sit = rit->second.subkeys.begin();
        std::advance(sit, index);

        if (pName && pcchName) {
            uint32_t maxch = mem.Read32(pcchName);
            for (uint32_t i = 0; i < sit->size() && i < maxch; i++)
                mem.Write16(pName + i * 2, (*sit)[i]);
            mem.Write16(pName + (uint32_t)sit->size() * 2, 0);
            mem.Write32(pcchName, (uint32_t)sit->size());
        }
        regs[0] = ERROR_SUCCESS;
        return true;
    }
    if (func == "RegQueryInfoKeyW") {
        LoadRegistry();
        /* R0=hKey, R1=lpClass, R2=lpcchClass, R3=lpReserved,
           stack[0]=lpcSubKeys, stack[1]=lpcbMaxSubKeyLen, stack[2]=lpcbMaxClassLen,
           stack[3]=lpcValues, stack[4]=lpcbMaxValueNameLen, stack[5]=lpcbMaxValueLen,
           stack[6]=lpcbSecurityDescriptor, stack[7]=lpftLastWriteTime */
        uint32_t hkey = regs[0];
        uint32_t pcSubKeys = ReadStackArg(regs, mem, 0);
        uint32_t pcValues = ReadStackArg(regs, mem, 3);

        auto kit = hkey_map.find(hkey);
        if (kit == hkey_map.end()) { regs[0] = ERROR_INVALID_HANDLE; return true; }
        auto rit = registry.find(kit->second);
        uint32_t num_subkeys = 0, num_values = 0;
        if (rit != registry.end()) {
            num_subkeys = (uint32_t)rit->second.subkeys.size();
            num_values = (uint32_t)rit->second.values.size();
        }
        if (pcSubKeys) mem.Write32(pcSubKeys, num_subkeys);
        if (pcValues) mem.Write32(pcValues, num_values);
        regs[0] = ERROR_SUCCESS;
        return true;
    }

    /* Resources */
    if (func == "LoadStringW") {
        uint32_t hmod = regs[0];
        uint32_t str_id = regs[1];
        uint32_t dst = regs[2];
        uint32_t maxlen = regs[3];
        if (maxlen > 4096) maxlen = 4096;

        uint32_t bundle_id = (str_id / 16) + 1;
        uint32_t string_idx = str_id % 16;

        uint32_t rsrc_rva = 0, rsrc_sz = 0;
        bool is_arm = false;
        if (hmod == emu_hinstance || hmod == 0) {
            is_arm = true;
            uint32_t base = emu_hinstance;
            uint32_t dos_lfanew = mem.Read32(base + 0x3C);
            uint32_t nt_addr = base + dos_lfanew;
            uint32_t num_rva_sizes = mem.Read32(nt_addr + 0x74);
            if (num_rva_sizes > IMAGE_DIRECTORY_ENTRY_RESOURCE) {
                rsrc_rva = mem.Read32(nt_addr + 0x78 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8);
                rsrc_sz = mem.Read32(nt_addr + 0x78 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8 + 4);
            }
            hmod = base;
        }
        for (auto& pair : loaded_dlls) {
            if (pair.second.base_addr == hmod) {
                is_arm = true;
                rsrc_rva = pair.second.pe_info.rsrc_rva;
                rsrc_sz = pair.second.pe_info.rsrc_size;
                break;
            }
        }

        if (is_arm && rsrc_rva) {
            uint32_t data_rva = 0, data_size = 0;
            if (FindResourceInPE(hmod, rsrc_rva, rsrc_sz, 6, bundle_id, data_rva, data_size)) {
                uint8_t* data = mem.Translate(hmod + data_rva);
                if (data) {
                    uint16_t* p = (uint16_t*)data;
                    for (uint32_t i = 0; i < string_idx && (uint8_t*)p < data + data_size; i++) {
                        uint16_t len = *p++;
                        p += len;
                    }
                    if ((uint8_t*)p < data + data_size) {
                        uint16_t len = *p++;
                        uint32_t copy_len = (len < maxlen - 1) ? len : maxlen - 1;
                        for (uint32_t i = 0; i < copy_len; i++) {
                            mem.Write16(dst + i * 2, p[i]);
                        }
                        mem.Write16(dst + copy_len * 2, 0);
                        regs[0] = copy_len;
                        printf("[THUNK] LoadStringW(0x%08X, %u) -> %u chars\n", hmod, str_id, copy_len);
                        return true;
                    }
                }
            }
            if (dst && maxlen > 0) mem.Write16(dst, 0);
            regs[0] = 0;
            printf("[THUNK] LoadStringW(0x%08X, %u) -> not found\n", hmod, str_id);
        } else {
            wchar_t buf[1024] = {};
            if (maxlen > 1024) maxlen = 1024;
            int ret = LoadStringW(GetModuleHandleW(NULL), str_id, buf, (int)maxlen);
            for (int i = 0; i <= ret && i < (int)maxlen; i++) {
                mem.Write16(dst + i * 2, buf[i]);
            }
            regs[0] = ret;
        }
        return true;
    }
    if (func == "LoadBitmapW") {
        uint32_t hmod = regs[0];
        uint32_t name_id = regs[1];

        bool is_arm_module = (hmod == emu_hinstance);
        for (auto& pair : loaded_dlls) {
            if (pair.second.base_addr == hmod) { is_arm_module = true; break; }
        }

        if (is_arm_module) {
            uint32_t rsrc_rva = 0, rsrc_sz = 0;
            if (hmod == emu_hinstance) {
                uint32_t dos_lfanew = mem.Read32(hmod + 0x3C);
                uint32_t nt_addr = hmod + dos_lfanew;
                uint32_t num_rva_sizes = mem.Read32(nt_addr + 0x74);
                if (num_rva_sizes > IMAGE_DIRECTORY_ENTRY_RESOURCE) {
                    rsrc_rva = mem.Read32(nt_addr + 0x78 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8);
                    rsrc_sz = mem.Read32(nt_addr + 0x78 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8 + 4);
                }
            }
            for (auto& pair : loaded_dlls) {
                if (pair.second.base_addr == hmod) {
                    rsrc_rva = pair.second.pe_info.rsrc_rva;
                    rsrc_sz = pair.second.pe_info.rsrc_size;
                    break;
                }
            }

            uint32_t data_rva = 0, data_size = 0;
            if (rsrc_rva && FindResourceInPE(hmod, rsrc_rva, rsrc_sz,
                                             (uint32_t)RT_BITMAP, name_id, data_rva, data_size)) {
                uint8_t* bmp_data = mem.Translate(hmod + data_rva);
                if (bmp_data && data_size > sizeof(BITMAPINFOHEADER)) {
                    BITMAPINFO* bmi = (BITMAPINFO*)bmp_data;
                    HDC hdc = GetDC(NULL);
                    int colors = 0;
                    if (bmi->bmiHeader.biBitCount <= 8)
                        colors = (bmi->bmiHeader.biClrUsed ? bmi->bmiHeader.biClrUsed : (1 << bmi->bmiHeader.biBitCount));
                    uint8_t* bits = bmp_data + sizeof(BITMAPINFOHEADER) + colors * sizeof(RGBQUAD);
                    HBITMAP hbm = CreateDIBitmap(hdc, &bmi->bmiHeader, CBM_INIT,
                                                  bits, bmi, DIB_RGB_COLORS);
                    ReleaseDC(NULL, hdc);
                    regs[0] = (uint32_t)(uintptr_t)hbm;
                    printf("[THUNK] LoadBitmapW(0x%08X, %u) -> HBITMAP=%p (from PE rsrc)\n",
                           hmod, name_id, hbm);
                } else {
                    regs[0] = 0;
                }
            } else {
                /* Resource not in emulated PE; try loading natively from the DLL file */
                HMODULE native_mod = GetNativeModuleForResources(hmod);
                if (native_mod) {
                    HBITMAP hbm = LoadBitmapW(native_mod, MAKEINTRESOURCEW(name_id));
                    regs[0] = (uint32_t)(uintptr_t)hbm;
                    printf("[THUNK] LoadBitmapW(0x%08X, %u) -> HBITMAP=%p (native fallback)\n",
                           hmod, name_id, hbm);
                } else {
                    printf("[THUNK] LoadBitmapW(0x%08X, %u) -> resource not found\n", hmod, name_id);
                    regs[0] = 0;
                }
            }
        } else {
            regs[0] = (uint32_t)(uintptr_t)LoadBitmapW((HINSTANCE)(intptr_t)(int32_t)hmod,
                                                         MAKEINTRESOURCEW(name_id));
        }
        return true;
    }
    if (func == "LoadImageW") {
        uint32_t hmod = regs[0];
        uint32_t name_id = regs[1];
        uint32_t type = regs[2];
        int cx = (int)regs[3];
        int cy = (int)ReadStackArg(regs, mem, 0);
        uint32_t fuLoad = ReadStackArg(regs, mem, 1);

        /* Check if this is an ARM module */
        bool is_arm_module = (hmod == emu_hinstance);
        for (auto& pair : loaded_dlls) {
            if (pair.second.base_addr == hmod) { is_arm_module = true; break; }
        }

        if (is_arm_module && type == IMAGE_BITMAP) {
            /* Load bitmap from ARM PE resources (same as LoadBitmapW) */
            uint32_t rsrc_rva = 0, rsrc_sz = 0;
            if (hmod == emu_hinstance) {
                uint32_t dos_lfanew = mem.Read32(hmod + 0x3C);
                uint32_t nt_addr = hmod + dos_lfanew;
                uint32_t num_rva_sizes = mem.Read32(nt_addr + 0x74);
                if (num_rva_sizes > IMAGE_DIRECTORY_ENTRY_RESOURCE) {
                    rsrc_rva = mem.Read32(nt_addr + 0x78 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8);
                    rsrc_sz = mem.Read32(nt_addr + 0x78 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8 + 4);
                }
            }
            for (auto& pair : loaded_dlls) {
                if (pair.second.base_addr == hmod) {
                    rsrc_rva = pair.second.pe_info.rsrc_rva;
                    rsrc_sz = pair.second.pe_info.rsrc_size;
                    break;
                }
            }

            uint32_t data_rva = 0, data_size = 0;
            if (rsrc_rva && FindResourceInPE(hmod, rsrc_rva, rsrc_sz,
                                             (uint32_t)RT_BITMAP, name_id, data_rva, data_size)) {
                uint8_t* bmp_data = mem.Translate(hmod + data_rva);
                if (bmp_data && data_size > sizeof(BITMAPINFOHEADER)) {
                    BITMAPINFO* bmi = (BITMAPINFO*)bmp_data;
                    HDC hdc = GetDC(NULL);
                    int colors = 0;
                    if (bmi->bmiHeader.biBitCount <= 8)
                        colors = (bmi->bmiHeader.biClrUsed ? bmi->bmiHeader.biClrUsed : (1 << bmi->bmiHeader.biBitCount));
                    uint8_t* bits = bmp_data + sizeof(BITMAPINFOHEADER) + colors * sizeof(RGBQUAD);
                    HBITMAP hbm = CreateDIBitmap(hdc, &bmi->bmiHeader, CBM_INIT,
                                                  bits, bmi, DIB_RGB_COLORS);
                    ReleaseDC(NULL, hdc);
                    regs[0] = (uint32_t)(uintptr_t)hbm;
                    printf("[THUNK] LoadImageW(0x%08X, %u, IMAGE_BITMAP) -> HBITMAP=%p (from PE rsrc)\n",
                           hmod, name_id, hbm);
                } else {
                    regs[0] = 0;
                }
            } else {
                printf("[THUNK] LoadImageW(0x%08X, %u, IMAGE_BITMAP) -> resource not found\n",
                       hmod, name_id);
                regs[0] = 0;
            }
        } else if (!is_arm_module || hmod == 0) {
            /* Non-ARM module or NULL (system resource) - use native API */
            regs[0] = (uint32_t)(uintptr_t)LoadImageW(
                (HINSTANCE)(intptr_t)(int32_t)hmod,
                MAKEINTRESOURCEW(name_id), type, cx, cy, fuLoad);
        } else {
            /* ARM module with non-bitmap type (icon, cursor) - try native resource loading */
            HMODULE native_mod = GetNativeModuleForResources(hmod);
            if (native_mod) {
                HANDLE h = LoadImageW(native_mod, MAKEINTRESOURCEW(name_id), type, cx, cy, fuLoad);
                regs[0] = (uint32_t)(uintptr_t)h;
                printf("[THUNK] LoadImageW(0x%08X, %u, type=%u) -> 0x%08X (native rsrc)\n",
                       hmod, name_id, type, regs[0]);
            } else {
                printf("[THUNK] LoadImageW(0x%08X, %u, type=%u) -> no native module for resources\n",
                       hmod, name_id, type);
                regs[0] = 0;
            }
        }
        return true;
    }
    if (func == "FindResourceW") {
        uint32_t hmod = regs[0];
        uint32_t name_arg = regs[1];
        uint32_t type_arg = regs[2];

        uint32_t rsrc_rva = 0, rsrc_sz = 0;
        if (hmod == emu_hinstance) {
            uint32_t dos_lfanew = mem.Read32(hmod + 0x3C);
            uint32_t nt_addr = hmod + dos_lfanew;
            uint32_t num_rva_sizes = mem.Read32(nt_addr + 0x74);
            if (num_rva_sizes > IMAGE_DIRECTORY_ENTRY_RESOURCE) {
                rsrc_rva = mem.Read32(nt_addr + 0x78 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8);
                rsrc_sz = mem.Read32(nt_addr + 0x78 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8 + 4);
            }
        }
        for (auto& pair : loaded_dlls) {
            if (pair.second.base_addr == hmod) {
                rsrc_rva = pair.second.pe_info.rsrc_rva;
                rsrc_sz = pair.second.pe_info.rsrc_size;
                break;
            }
        }

        uint32_t data_rva = 0, data_size = 0;
        if (rsrc_rva && FindResourceInPE(hmod, rsrc_rva, rsrc_sz,
                                         type_arg, name_arg, data_rva, data_size)) {
            uint32_t fake = next_rsrc_handle++;
            rsrc_map[fake] = { data_rva, data_size, hmod };
            regs[0] = fake;
            printf("[THUNK] FindResourceW(0x%08X, %u, %u) -> 0x%08X (rva=0x%X, size=%u)\n",
                   hmod, name_arg, type_arg, fake, data_rva, data_size);
        } else {
            printf("[THUNK] FindResourceW(0x%08X, %u, %u) -> NOT FOUND\n",
                   hmod, name_arg, type_arg);
            regs[0] = 0;
        }
        return true;
    }
    if (func == "LoadResource") {
        uint32_t hrsrc_emu = regs[1];
        auto it = rsrc_map.find(hrsrc_emu);
        if (it != rsrc_map.end()) {
            uint32_t addr = it->second.module_base + it->second.data_rva;
            regs[0] = addr;
            printf("[THUNK] LoadResource -> 0x%08X (%u bytes)\n", addr, it->second.data_size);
        } else {
            regs[0] = 0;
        }
        return true;
    }
    if (func == "SizeofResource") {
        uint32_t hrsrc_emu = regs[1];
        auto it = rsrc_map.find(hrsrc_emu);
        if (it != rsrc_map.end()) {
            regs[0] = it->second.data_size;
        } else {
            regs[0] = 0;
        }
        return true;
    }
    if (func == "FreeLibrary") {
        printf("[STUB] FreeLibrary(0x%08X) -> 1\n", regs[0]);
        regs[0] = 1;
        return true;
    }

    /* Debug */
    if (func == "OutputDebugStringW") {
        std::wstring msg = ReadWStringFromEmu(mem, regs[0]);
        printf("[DEBUG] %ls\n", msg.c_str());
        return true;
    }
    if (func == "NKDbgPrintfW") {
        std::wstring msg = ReadWStringFromEmu(mem, regs[0]);
        printf("[NKDbg] %ls\n", msg.c_str());
        return true;
    }

    /* File I/O */
    if (func == "CreateFileW") {
        std::wstring wce_path = ReadWStringFromEmu(mem, regs[0]);
        uint32_t access = regs[1];
        uint32_t share = regs[2];
        /* regs[3] = lpSecurityAttributes (ignored) */
        uint32_t creation = ReadStackArg(regs, mem, 0);
        uint32_t flags = ReadStackArg(regs, mem, 1);
        /* stack arg 2 = hTemplate (ignored) */

        std::wstring host_path = MapWinCEPath(wce_path);
        HANDLE h = CreateFileW(host_path.c_str(), access, share, NULL, creation, flags, NULL);
        regs[0] = WrapHandle(h);
        printf("[THUNK] CreateFileW('%ls') -> mapped='%ls' handle=0x%08X\n",
               wce_path.c_str(), host_path.c_str(), regs[0]);
        return true;
    }
    if (func == "ReadFile") {
        HANDLE h = UnwrapHandle(regs[0]);
        uint32_t buf_addr = regs[1];
        uint32_t bytes_to_read = regs[2];
        uint32_t bytes_read_addr = regs[3];

        /* Sanity check buffer size */
        if (bytes_to_read > 64 * 1024 * 1024) {
            printf("[THUNK] ReadFile: request too large (0x%X bytes), failing\n", bytes_to_read);
            if (bytes_read_addr) mem.Write32(bytes_read_addr, 0);
            SetLastError(ERROR_INVALID_PARAMETER);
            regs[0] = 0;
            return true;
        }

        std::vector<uint8_t> buf(bytes_to_read);
        DWORD bytes_read = 0;
        BOOL ret = ReadFile(h, buf.data(), bytes_to_read, &bytes_read, NULL);
        if (ret && bytes_read > 0) {
            /* Copy byte-by-byte to handle cross-region boundaries safely */
            for (DWORD i = 0; i < bytes_read; i++)
                mem.Write8(buf_addr + i, buf[i]);
        }
        if (bytes_read_addr) mem.Write32(bytes_read_addr, bytes_read);
        regs[0] = ret;
        return true;
    }
    if (func == "WriteFile") {
        HANDLE h = UnwrapHandle(regs[0]);
        uint32_t buf_addr = regs[1];
        uint32_t bytes_to_write = regs[2];
        uint32_t bytes_written_addr = regs[3];

        if (bytes_to_write > 64 * 1024 * 1024) {
            printf("[THUNK] WriteFile: request too large (0x%X bytes), failing\n", bytes_to_write);
            if (bytes_written_addr) mem.Write32(bytes_written_addr, 0);
            SetLastError(ERROR_INVALID_PARAMETER);
            regs[0] = 0;
            return true;
        }

        std::vector<uint8_t> buf(bytes_to_write);
        for (uint32_t i = 0; i < bytes_to_write; i++)
            buf[i] = mem.Read8(buf_addr + i);
        DWORD bytes_written = 0;
        BOOL ret = WriteFile(h, buf.data(), bytes_to_write, &bytes_written, NULL);
        if (bytes_written_addr) mem.Write32(bytes_written_addr, bytes_written);
        regs[0] = ret;
        return true;
    }
    if (func == "GetFileSize") {
        HANDLE h = UnwrapHandle(regs[0]);
        uint32_t high_addr = regs[1];
        DWORD high = 0;
        DWORD size = GetFileSize(h, high_addr ? &high : NULL);
        if (high_addr) mem.Write32(high_addr, high);
        regs[0] = size;
        return true;
    }
    if (func == "SetFilePointer") {
        HANDLE h = UnwrapHandle(regs[0]);
        LONG dist = (LONG)regs[1];
        uint32_t high_addr = regs[2];
        DWORD method = regs[3];
        LONG high = 0;
        if (high_addr) high = (LONG)mem.Read32(high_addr);
        DWORD result = SetFilePointer(h, dist, high_addr ? &high : NULL, method);
        if (high_addr) mem.Write32(high_addr, (uint32_t)high);
        regs[0] = result;
        return true;
    }
    if (func == "GetFileAttributesW") {
        std::wstring wce_path = ReadWStringFromEmu(mem, regs[0]);
        std::wstring host_path = MapWinCEPath(wce_path);
        regs[0] = GetFileAttributesW(host_path.c_str());
        printf("[THUNK] GetFileAttributesW('%ls') -> 0x%08X\n", wce_path.c_str(), regs[0]);
        return true;
    }
    if (func == "DeleteFileW") {
        std::wstring wce_path = ReadWStringFromEmu(mem, regs[0]);
        std::wstring host_path = MapWinCEPath(wce_path);
        regs[0] = DeleteFileW(host_path.c_str());
        printf("[THUNK] DeleteFileW('%ls') -> %u\n", wce_path.c_str(), regs[0]);
        return true;
    }
    if (func == "MoveFileW") {
        std::wstring src = ReadWStringFromEmu(mem, regs[0]);
        std::wstring dst = ReadWStringFromEmu(mem, regs[1]);
        std::wstring host_src = MapWinCEPath(src);
        std::wstring host_dst = MapWinCEPath(dst);
        regs[0] = MoveFileW(host_src.c_str(), host_dst.c_str());
        return true;
    }
    if (func == "CreateDirectoryW") {
        std::wstring wce_path = ReadWStringFromEmu(mem, regs[0]);
        std::wstring host_path = MapWinCEPath(wce_path);
        regs[0] = CreateDirectoryW(host_path.c_str(), NULL);
        printf("[THUNK] CreateDirectoryW('%ls') -> %u\n", wce_path.c_str(), regs[0]);
        return true;
    }
    if (func == "RemoveDirectoryW") {
        std::wstring wce_path = ReadWStringFromEmu(mem, regs[0]);
        std::wstring host_path = MapWinCEPath(wce_path);
        regs[0] = RemoveDirectoryW(host_path.c_str());
        return true;
    }
    if (func == "FindFirstFileW") {
        std::wstring wce_pattern = ReadWStringFromEmu(mem, regs[0]);
        uint32_t find_data_addr = regs[1];
        std::wstring host_pattern = MapWinCEPath(wce_pattern);

        WIN32_FIND_DATAW fd = {};
        HANDLE h = FindFirstFileW(host_pattern.c_str(), &fd);
        if (h != INVALID_HANDLE_VALUE) {
            WriteFindDataToEmu(mem, find_data_addr, fd);
        }
        regs[0] = WrapHandle(h);
        printf("[THUNK] FindFirstFileW('%ls') -> mapped='%ls' handle=0x%08X%s\n",
               wce_pattern.c_str(), host_pattern.c_str(), regs[0],
               h == INVALID_HANDLE_VALUE ? " (NOT FOUND)" : "");
        return true;
    }
    if (func == "FindNextFileW") {
        HANDLE h = UnwrapHandle(regs[0]);
        uint32_t find_data_addr = regs[1];

        WIN32_FIND_DATAW fd = {};
        BOOL ret = FindNextFileW(h, &fd);
        if (ret) {
            WriteFindDataToEmu(mem, find_data_addr, fd);
        }
        regs[0] = ret;
        return true;
    }
    if (func == "FindClose") {
        uint32_t fake = regs[0];
        HANDLE h = UnwrapHandle(fake);
        regs[0] = FindClose(h);
        RemoveHandle(fake);
        return true;
    }

    /* Process info */
    if (func == "GetProcessVersion") {
        regs[0] = 0x0400000A;
        return true;
    }
    if (func == "GetOwnerProcess") {
        regs[0] = GetCurrentProcessId();
        return true;
    }
    if (func == "GetStartupInfoW") {
        for (int i = 0; i < 68; i += 4) mem.Write32(regs[0] + i, 0);
        mem.Write32(regs[0], 68);
        return true;
    }

    /* Stubs for misc functions */
    if (func == "DisableThreadLibraryCalls") { printf("[STUB] DisableThreadLibraryCalls -> 1\n"); regs[0] = 1; return true; }
    if (func == "FlushInstructionCache") { printf("[STUB] FlushInstructionCache -> 1\n"); regs[0] = 1; return true; }
    if (func == "GetProcessIndexFromID") { printf("[STUB] GetProcessIndexFromID -> 1\n"); regs[0] = 1; return true; }
    if (func == "GlobalMemoryStatus") {
        uint32_t ptr = regs[0];
        if (ptr) {
            MEMORYSTATUS ms = {};
            ms.dwLength = sizeof(ms);
            GlobalMemoryStatus(&ms);
            mem.Write32(ptr + 0,  32);
            mem.Write32(ptr + 4,  ms.dwMemoryLoad);
            mem.Write32(ptr + 8,  (uint32_t)std::min(ms.dwTotalPhys,    (SIZE_T)UINT32_MAX));
            mem.Write32(ptr + 12, (uint32_t)std::min(ms.dwAvailPhys,    (SIZE_T)UINT32_MAX));
            mem.Write32(ptr + 16, (uint32_t)std::min(ms.dwTotalPageFile, (SIZE_T)UINT32_MAX));
            mem.Write32(ptr + 20, (uint32_t)std::min(ms.dwAvailPageFile, (SIZE_T)UINT32_MAX));
            mem.Write32(ptr + 24, (uint32_t)std::min(ms.dwTotalVirtual,  (SIZE_T)UINT32_MAX));
            mem.Write32(ptr + 28, (uint32_t)std::min(ms.dwAvailVirtual,  (SIZE_T)UINT32_MAX));
        }
        return true;
    }
    if (func == "GetVersionExW") {
        if (regs[0]) {
            mem.Write32(regs[0] + 4, 4);
            mem.Write32(regs[0] + 8, 21);
            mem.Write32(regs[0] + 12, 0);
            mem.Write32(regs[0] + 16, 0);
        }
        regs[0] = 1;
        return true;
    }
    if (func == "SystemParametersInfoW") {
        regs[0] = SystemParametersInfoW(regs[0], regs[1], NULL, regs[3]);
        return true;
    }

    /* Gesture stubs */
    if (func == "RegisterDefaultGestureHandler" || func == "GetGestureInfo" ||
        func == "GetGestureExtraArguments" || func == "CloseGestureInfoHandle") {
        printf("[STUB] %s -> 0\n", func.c_str());
        regs[0] = 0;
        return true;
    }

    /* Shell stubs */
    if (func == "SHGetSpecialFolderPath") { printf("[STUB] SHGetSpecialFolderPath -> 0\n"); regs[0] = 0; return true; }
    if (func == "ShellExecuteEx") { printf("[STUB] ShellExecuteEx -> 0\n"); regs[0] = 0; return true; }
    if (func == "SHLoadDIBitmap") { printf("[STUB] SHLoadDIBitmap -> 0\n"); regs[0] = 0; return true; }

    /* Common controls */
    if (func == "ImageList_Create") {
        regs[0] = (uint32_t)(uintptr_t)ImageList_Create(regs[0], regs[1], regs[2], regs[3],
                                                         ReadStackArg(regs, mem, 0));
        return true;
    }
    if (func == "ImageList_Destroy") {
        regs[0] = ImageList_Destroy((HIMAGELIST)(intptr_t)(int32_t)regs[0]);
        return true;
    }
    if (func == "ImageList_Add") {
        regs[0] = ImageList_Add((HIMAGELIST)(intptr_t)(int32_t)regs[0],
                                (HBITMAP)(intptr_t)(int32_t)regs[1], (HBITMAP)(intptr_t)(int32_t)regs[2]);
        return true;
    }
    if (func == "ImageList_Draw") {
        regs[0] = ImageList_Draw((HIMAGELIST)(intptr_t)(int32_t)regs[0], regs[1],
                                 (HDC)(intptr_t)(int32_t)regs[2], regs[3],
                                 ReadStackArg(regs, mem, 0), ReadStackArg(regs, mem, 1));
        return true;
    }
    if (func == "ImageList_DrawEx") {
        regs[0] = ImageList_DrawEx((HIMAGELIST)(intptr_t)(int32_t)regs[0], regs[1],
                                    (HDC)(intptr_t)(int32_t)regs[2], regs[3],
                                    ReadStackArg(regs, mem, 0), ReadStackArg(regs, mem, 1),
                                    ReadStackArg(regs, mem, 2), ReadStackArg(regs, mem, 3),
                                    ReadStackArg(regs, mem, 4), ReadStackArg(regs, mem, 5));
        return true;
    }
    if (func == "ImageList_GetImageCount") {
        regs[0] = ImageList_GetImageCount((HIMAGELIST)(intptr_t)(int32_t)regs[0]);
        return true;
    }
    if (func == "ImageList_GetIconSize") {
        int cx, cy;
        BOOL ret = ImageList_GetIconSize((HIMAGELIST)(intptr_t)(int32_t)regs[0], &cx, &cy);
        if (regs[1]) mem.Write32(regs[1], cx);
        if (regs[2]) mem.Write32(regs[2], cy);
        regs[0] = ret;
        return true;
    }

    /* IMM stubs */
    if (func == "ImmAssociateContext" || func == "ImmGetContext" || func == "ImmReleaseContext") {
        printf("[STUB] %s -> 0\n", func.c_str());
        regs[0] = 0;
        return true;
    }

    /* Clipboard stubs */
    if (func == "OpenClipboard") { printf("[STUB] OpenClipboard -> 1\n"); regs[0] = 1; return true; }
    if (func == "CloseClipboard") { printf("[STUB] CloseClipboard -> 1\n"); regs[0] = 1; return true; }
    if (func == "EmptyClipboard") { printf("[STUB] EmptyClipboard -> 1\n"); regs[0] = 1; return true; }
    if (func == "GetClipboardData") { printf("[STUB] GetClipboardData -> 0\n"); regs[0] = 0; return true; }
    if (func == "SetClipboardData") { printf("[STUB] SetClipboardData -> 0\n"); regs[0] = 0; return true; }
    if (func == "IsClipboardFormatAvailable") { printf("[STUB] IsClipboardFormatAvailable -> 0\n"); regs[0] = 0; return true; }
    if (func == "EnumClipboardFormats") { printf("[STUB] EnumClipboardFormats -> 0\n"); regs[0] = 0; return true; }

    /* Caret stubs */
    if (func == "CreateCaret" || func == "HideCaret" || func == "ShowCaret") {
        printf("[STUB] %s -> 1\n", func.c_str());
        regs[0] = 1;
        return true;
    }

    /* Cursor stubs */
    if (func == "CreateCursor" || func == "DestroyCursor" || func == "DestroyIcon" ||
        func == "DrawIconEx" || func == "ClipCursor" || func == "GetClipCursor" ||
        func == "GetCursor" || func == "SetCursorPos" || func == "ShowCursor") {
        printf("[STUB] %s -> 0\n", func.c_str());
        regs[0] = 0;
        return true;
    }

    /* Sound stubs */
    if (func == "sndPlaySoundW") {
        printf("[STUB] sndPlaySoundW -> 1\n");
        regs[0] = 1;
        return true;
    }
    if (func == "waveOutSetVolume") {
        regs[0] = 0; /* MMSYSERR_NOERROR */
        return true;
    }

    /* Ras stubs */
    if (func == "RasDial" || func == "RasHangup" || func == "RasHangUp") {
        printf("[STUB] %s -> 0\n", func.c_str());
        regs[0] = 0;
        return true;
    }

    /* C runtime stubs */
    if (func == "_purecall") {
        printf("[THUNK] _purecall - abort\n");
        regs[0] = 0;
        return true;
    }
    if (func == "terminate") {
        printf("[THUNK] terminate() called\n");
        ExitProcess(3);
        return true;
    }
    if (func == "__security_gen_cookie" || func == "__security_gen_cookie2") {
        printf("[STUB] %s -> 0xBB40E64E\n", func.c_str());
        regs[0] = 0xBB40E64E;
        return true;
    }
    if (func == "CeGenRandom") {
        uint32_t len = regs[0];
        uint32_t buf = regs[1];
        for (uint32_t i = 0; i < len; i++)
            mem.Write8(buf + i, (uint8_t)(rand() & 0xFF));
        regs[0] = 1;
        return true;
    }
    if (func == "MulDiv") {
        regs[0] = MulDiv((int)regs[0], (int)regs[1], (int)regs[2]);
        return true;
    }
    if (func == "GetAPIAddress") { printf("[STUB] GetAPIAddress -> 0\n"); regs[0] = 0; return true; }
    if (func == "WaitForAPIReady") { printf("[STUB] WaitForAPIReady -> 0\n"); regs[0] = 0; return true; }
    if (func == "__GetUserKData") { printf("[STUB] __GetUserKData -> 0\n"); regs[0] = 0; return true; }
    if (func == "EventModify") { printf("[STUB] EventModify -> 1\n"); regs[0] = 1; return true; }
    if (func == "GlobalAddAtomW") { printf("[STUB] GlobalAddAtomW -> 1\n"); regs[0] = 1; return true; }
    if (func == "_setjmp3" || func == "_except_handler4_common") { printf("[STUB] %s -> 0\n", func.c_str()); regs[0] = 0; return true; }

    /* Platform-specific ordinals */
    if (func == "__PlatformSpecific2005" || func == "__PlatformSpecific2008") {
        printf("[STUB] %s -> 0\n", func.c_str());
        regs[0] = 0;
        return true;
    }

    /* Process/thread stubs */
    if (func == "CreateThread" || func == "CreateProcessW" || func == "TerminateThread" ||
        func == "SetThreadPriority" || func == "GetExitCodeProcess" || func == "OpenProcess" ||
        func == "WaitForMultipleObjects" || func == "CreateFileMappingW" ||
        func == "MapViewOfFile" || func == "UnmapViewOfFile") {
        printf("[STUB] %s -> 0\n", func.c_str());
        regs[0] = 0;
        return true;
    }

    return false;
}
