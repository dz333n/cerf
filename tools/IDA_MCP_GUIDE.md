# IDA Pro MCP Server Guide

## Overview

IDA Pro instances are connected via MCP (Model Context Protocol) servers, allowing
Claude to decompile functions, inspect types, read disassembly, and search through
binary databases. This is extremely powerful for understanding WinCE DLL internals.

## Available IDA Instances

Each instance is a separate IDA Pro database connected via MCP:

| MCP Server Name             | Description                                    |
|-----------------------------|------------------------------------------------|
| `ida-ceshell`               | ceshell.dll - WinCE shell extension library    |
| `ida-commctrl`              | commctrl.dll - Common controls (ListView, etc) |
| `ida-commdlg`               | commdlg.dll - Common dialogs (Open/Save, etc)  |
| `ida-target-app`            | Currently loaded target app being debugged      |
| `ida-windows-ce-original-coredll` | Original WinCE coredll.dll (reference)   |

**Target app** changes per debugging session. Ask the user to switch it if needed.
You can also ask the user to open additional IDA instances for other DLLs.

## Available Tools (per instance)

All tools are prefixed with `mcp__ida-<instance>__ida_`. Load them with ToolSearch
before use. Key tools:

### Decompilation & Disassembly
- `ida_decompile` - **Most useful!** Decompile a function to C pseudocode
- `ida_get_disasm` - Get disassembly for an address range
- `ida_get_bytes` - Read raw bytes at an address

### Function Discovery
- `ida_list_functions` - List all functions (with optional filter)
- `ida_get_exports` - List exported functions
- `ida_get_imports` - List imported functions
- `ida_get_function_context` - Get full context of a function (callers, callees, etc)

### Cross-References
- `ida_get_xrefs` - Get cross-references to/from an address (who calls this? what does it call?)

### Types & Structures
- `ida_list_structs` - List all structures
- `ida_get_struct` - Get struct definition
- `ida_list_enums` - List all enums
- `ida_get_enum` - Get enum definition
- `ida_get_vtable` - Get virtual function table

### Search & Navigation
- `ida_get_names` - Search named addresses (functions, globals, etc)
- `ida_get_strings` - Search string references in the binary
- `ida_search_bytes` - Search for byte patterns
- `ida_get_segments` - List binary segments
- `ida_get_address_info` - Get info about a specific address
- `ida_info` - Get general database info

### Annotation (use sparingly)
- `ida_rename` - Rename an address/function
- `ida_set_comment` - Set a comment at an address
- `ida_set_func_comment` - Set a function comment
- `ida_set_type` - Set type information for an address
- `ida_create_function` - Create a new function at an address
- `ida_delete_function` - Delete a function definition

## Usage Workflow

### Step 1: Load tools with ToolSearch
```
ToolSearch query: "+ida-commctrl decompile"
```
Or to load all tools for an instance:
```
ToolSearch query: "+ida-commctrl"
```

### Step 2: Find the function you need
```
ida_list_functions with filter (e.g., "ListView", "CreateWindow")
ida_get_exports to see exported APIs
ida_get_names to search by name pattern
```

### Step 3: Decompile it
```
ida_decompile with the function address or name
```

### Step 4: Understand callers/callees
```
ida_get_xrefs to see who calls this function
ida_get_function_context for full picture
```

## Common Use Cases

### "How does commctrl handle WM_NOTIFY for ListView?"
1. Load ida-commctrl tools
2. Search for ListView-related functions: `ida_list_functions` with filter "ListView"
3. Decompile the window procedure: `ida_decompile`
4. Follow cross-references to understand message handling

### "What does coredll's CreateWindowExW actually do?"
1. Load ida-windows-ce-original-coredll tools
2. Find CreateWindowExW: `ida_get_exports` or `ida_get_names`
3. Decompile it: `ida_decompile`

### "Why is the target app crashing at address 0x12345?"
1. Load ida-target-app tools
2. Get info: `ida_get_address_info` at 0x12345
3. Decompile the containing function: `ida_decompile`
4. Check xrefs: `ida_get_xrefs` to understand call chain

## Important Notes

- **Load tools first!** Always use ToolSearch before calling any IDA tool
- **Target app is session-specific** - ask user to change it if needed
- **Don't modify annotations** (rename, set_comment, etc.) unless the user asks
- **Addresses are hex** - functions are identified by address or name
- **ARM code** - all WinCE DLLs are ARM binaries; the decompiler shows C pseudocode
- **Ask for more instances** - if you need to look at a DLL not currently loaded
  (e.g., ole32.dll, aygshell.dll), ask the user to open it in IDA
