# Explorer.exe Status

## Working
- Desktop shell loads and displays icons (My Device, Recycle Bin, SampleText)
- Taskbar with Start button and clock
- Double-click / Enter on desktop icons opens Explore window
- **Explore window navigation**: Navigate2 successfully navigates to `\` (root)
  - File browser menus (File, Edit, View, Go, Favorites) display correctly
  - Shell view created, items populated (directories listed from VFS root)
  - Folder icons render correctly (iImage callbacks work)
  - shdocvw COM initialization chain: SetOwner QI(IBrowserService/IShellBrowser/IServiceProvider) all succeed

## Known Issues

### Item Positioning in Explore ListView
- **Status**: OPEN
- 23 items inserted but most clustered at wrong positions (only last 2 visible)
- Root cause: ARM commctrl defers item positioning via PostMessage(WM_USER). These messages
  get dispatched while the ListView is still at its initial 320x240 size. Items get positioned
  for that small size, then the window resizes to full screen but items keep old positions.
- LVM_ARRANGE is sent on first WM_PAINT and after LVM_SORTITEMS, but items don't re-arrange
- WM_WINDOWPOSCHANGED is marshaled correctly (64-bit WINDOWPOS -> ARM 32-bit)
- Possible fix: ensure sizeClient is updated before items are arranged, or force arrange after resize

### Missing Title Bar
- Explore window appears without title bar / caption
- May be related to layout translation (WinCE thin frames vs desktop thick frames)

### Missing Toolbar / Address Bar
- Small empty control visible in top-left of Explore window
- Toolbar creation may be failing or toolbar is at wrong position

### X Button Infinite Loop (calc.exe regression)
- Do NOT click X button on calc.exe — causes infinite loop
