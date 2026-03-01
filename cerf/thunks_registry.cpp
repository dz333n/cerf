/* Registry thunks: RegOpenKeyEx, RegCreateKeyEx, RegCloseKey, etc. */
#include "win32_thunks.h"
#include <cstdio>

void Win32Thunks::RegisterRegistryHandlers() {
    Thunk("RegOpenKeyExW", 461, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LoadRegistry();
        uint32_t parent_hkey = regs[0];
        std::wstring subkey;
        if (regs[1]) subkey = ReadWStringFromEmu(mem, regs[1]);
        uint32_t phkResult = ReadStackArg(regs, mem, 0);
        std::wstring full_path = ResolveHKey(parent_hkey, subkey);
        auto it = registry.find(full_path);
        if (it == registry.end()) {
            printf("[REG] RegOpenKeyExW('%ls') -> NOT FOUND\n", full_path.c_str());
            regs[0] = ERROR_FILE_NOT_FOUND; return true;
        }
        uint32_t fake = next_fake_hkey++;
        hkey_map[fake] = full_path;
        if (phkResult) mem.Write32(phkResult, fake);
        printf("[REG] RegOpenKeyExW('%ls') -> 0x%08X\n", full_path.c_str(), fake);
        regs[0] = ERROR_SUCCESS; return true;
    });
    Thunk("RegCreateKeyExW", 456, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LoadRegistry();
        uint32_t parent_hkey = regs[0];
        std::wstring subkey;
        if (regs[1]) subkey = ReadWStringFromEmu(mem, regs[1]);
        uint32_t phkResult = ReadStackArg(regs, mem, 3);
        uint32_t pDisposition = ReadStackArg(regs, mem, 4);
        std::wstring full_path = ResolveHKey(parent_hkey, subkey);
        bool existed = registry.find(full_path) != registry.end();
        registry[full_path];
        EnsureParentKeys(full_path);
        uint32_t fake = next_fake_hkey++;
        hkey_map[fake] = full_path;
        if (phkResult) mem.Write32(phkResult, fake);
        if (pDisposition) mem.Write32(pDisposition, existed ? 2 : 1);
        regs[0] = ERROR_SUCCESS; return true;
    });
    Thunk("RegCloseKey", 455, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        hkey_map.erase(regs[0]); SaveRegistry();
        regs[0] = ERROR_SUCCESS; return true;
    });
    Thunk("RegQueryValueExW", 463, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LoadRegistry();
        uint32_t hkey = regs[0];
        std::wstring value_name;
        if (regs[1]) value_name = ReadWStringFromEmu(mem, regs[1]);
        uint32_t pType = regs[3];
        uint32_t pData = ReadStackArg(regs, mem, 0);
        uint32_t pcbData = ReadStackArg(regs, mem, 1);
        auto kit = hkey_map.find(hkey);
        if (kit == hkey_map.end()) { regs[0] = ERROR_INVALID_HANDLE; return true; }
        auto rit = registry.find(kit->second);
        if (rit == registry.end()) { regs[0] = ERROR_FILE_NOT_FOUND; return true; }
        auto vit = rit->second.values.find(value_name);
        if (vit == rit->second.values.end()) { regs[0] = ERROR_FILE_NOT_FOUND; return true; }
        const RegValue& val = vit->second;
        if (pType) mem.Write32(pType, val.type);
        uint32_t data_size = (uint32_t)val.data.size();
        if (pcbData) {
            uint32_t buf_size = mem.Read32(pcbData);
            mem.Write32(pcbData, data_size);
            if (pData && buf_size >= data_size) {
                for (uint32_t i = 0; i < data_size; i++) mem.Write8(pData + i, val.data[i]);
            } else if (pData) { regs[0] = ERROR_MORE_DATA; return true; }
        }
        regs[0] = ERROR_SUCCESS; return true;
    });
    Thunk("RegSetValueExW", 464, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LoadRegistry();
        uint32_t hkey = regs[0];
        std::wstring value_name;
        if (regs[1]) value_name = ReadWStringFromEmu(mem, regs[1]);
        uint32_t type = regs[3];
        uint32_t pData = ReadStackArg(regs, mem, 0);
        uint32_t cbData = ReadStackArg(regs, mem, 1);
        auto kit = hkey_map.find(hkey);
        if (kit == hkey_map.end()) { regs[0] = ERROR_INVALID_HANDLE; return true; }
        RegValue val; val.type = type;
        if (cbData > 0 && cbData < 0x10000) {
            val.data.resize(cbData);
            for (uint32_t i = 0; i < cbData; i++) val.data[i] = mem.Read8(pData + i);
        }
        registry[kit->second].values[value_name] = val;
        regs[0] = ERROR_SUCCESS; return true;
    });
    Thunk("RegDeleteKeyW", 457, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t hkey = regs[0];
        std::wstring subkey;
        if (regs[1]) subkey = ReadWStringFromEmu(mem, regs[1]);
        auto kit = hkey_map.find(hkey);
        std::wstring path = (kit != hkey_map.end()) ? kit->second + L"\\" + subkey : subkey;
        registry.erase(path);
        regs[0] = ERROR_SUCCESS; return true;
    });
    Thunk("RegDeleteValueW", 458, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t hkey = regs[0];
        std::wstring value_name;
        if (regs[1]) value_name = ReadWStringFromEmu(mem, regs[1]);
        auto kit = hkey_map.find(hkey);
        if (kit != hkey_map.end()) {
            auto rit = registry.find(kit->second);
            if (rit != registry.end()) rit->second.values.erase(value_name);
        }
        regs[0] = ERROR_SUCCESS; return true;
    });
    Thunk("RegEnumValueW", 459, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LoadRegistry();
        uint32_t hkey = regs[0], index = regs[1], pName = regs[2], pcchName = regs[3];
        uint32_t pType = ReadStackArg(regs, mem, 1);
        uint32_t pData = ReadStackArg(regs, mem, 2);
        uint32_t pcbData = ReadStackArg(regs, mem, 3);
        auto kit = hkey_map.find(hkey);
        if (kit == hkey_map.end()) { regs[0] = ERROR_INVALID_HANDLE; return true; }
        auto rit = registry.find(kit->second);
        if (rit == registry.end() || index >= rit->second.values.size()) {
            regs[0] = ERROR_NO_MORE_ITEMS; return true;
        }
        auto vit = rit->second.values.begin();
        std::advance(vit, index);
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
        regs[0] = ERROR_SUCCESS; return true;
    });
    Thunk("RegEnumKeyExW", 460, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LoadRegistry();
        uint32_t hkey = regs[0], index = regs[1], pName = regs[2], pcchName = regs[3];
        auto kit = hkey_map.find(hkey);
        if (kit == hkey_map.end()) { regs[0] = ERROR_INVALID_HANDLE; return true; }
        auto rit = registry.find(kit->second);
        if (rit == registry.end() || index >= rit->second.subkeys.size()) {
            regs[0] = ERROR_NO_MORE_ITEMS; return true;
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
        regs[0] = ERROR_SUCCESS; return true;
    });
    Thunk("RegQueryInfoKeyW", 462, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LoadRegistry();
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
        regs[0] = ERROR_SUCCESS; return true;
    });
}
