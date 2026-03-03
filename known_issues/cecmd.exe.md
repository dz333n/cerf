# cecmd.exe (Total Commander/CE) - Known Issues

## 1. Black ListView column headers

**Description**: The SysHeader32 column headers in the file list panels render with a black/unstyled background.

**Now**: Headers appear as plain black bars with white text, no 3D button styling.

**Expected**: Headers should have standard Windows 3D button appearance (raised, gray background) as seen in real WinCE.

---

## 2. No file/folder icons in ListView rows

**Description**: The file listing in both panels shows no icons next to file/folder names. On real WinCE, each row has a small icon (folder icon for directories, file type icons for files).

**Now**: Only text is displayed in each row, no icons.

**Expected**: Each row should display a 16x16 icon (folder, file, etc.) retrieved via SHGetFileInfo or ImageList.

---

## 3. Black areas in Properties dialog

**Description**: The Properties dialog (Alt+Enter on a file/folder) has large black rectangular areas where styled content should appear.

**Now**: The top area of the Properties dialog is solid black. The tab control area background is black.

**Expected**: The top area should show a file/folder icon with the item name. Tab control should have a proper gray background with "General" and "Disk space" tabs.

---

## 4. No icon in Properties dialog

**Description**: The Properties dialog should display a large icon representing the selected item type (folder icon, file icon, etc.).

**Now**: No icon is rendered; the area is black.

**Expected**: A folder or file icon should appear in the upper-left area of the Properties dialog, matching the item type.

---

## Screenshots

- Current: `screenshots/cecmd_current.png`
- Expected: See reference screenshots provided by user (real WinCE device running cecmd.exe)
