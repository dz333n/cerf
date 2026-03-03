# commctrl.dll (Common Controls) - Known Issues

## 1. Command bar close (X) and help (?) buttons have no icons

**Description**: WinCE command bars (the title/menu bar area) typically show an X button (close) and often a ? button (help) in the top-right corner. These buttons exist but render without their icon glyphs.

**Now**: The X and ? buttons appear as blank/empty rectangles with no visible icon inside.

**Expected**: The X button should show a visible close glyph. The ? button should show a question mark glyph. These are drawn by the command bar implementation in commctrl.dll and rely on proper image list / bitmap rendering.

**Affects**: Nearly all WinCE applications that use command bars (Total Commander, Solitaire, etc.).
