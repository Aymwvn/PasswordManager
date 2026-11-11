# Opening PasswordManager with a keyboard shortcut

Windows' own "Shortcut key" box only accepts **Ctrl+Alt+<key>** (it adds Ctrl+Alt for you), so a
Win-key combination such as **Win+Alt+P** needs a tiny helper. Pick one of the two options.

## Option 1: Ctrl+Alt+P (no extra software)

```bat
cd %USERPROFILE%\Desktop\PasswordManager
packaging\create_shortcut.bat
```

This creates a Start Menu shortcut named *PasswordManager* with the hotkey **Ctrl+Alt+P**. It
points at the built `.exe` if you made one (`dist\PasswordManager\PasswordManager.exe`), otherwise
at `.venv\Scripts\pm-app.exe`. You can also just type "PasswordManager" in the Start menu.

## Option 2: Win+Alt+P (AutoHotkey)

1. Install AutoHotkey v2: `winget install AutoHotkey.AutoHotkey`
   (if that ID isn't found, run `winget search autohotkey`).
2. Double-click `packaging\pm-hotkey.ahk`. A green "H" icon appears in the tray. Press **Win+Alt+P**.
3. To start it at every login: press **Win+R**, type `shell:startup`, and drop a shortcut to
   `pm-hotkey.ahk` into that folder (right-click the file, Show more options, Create shortcut).

The script only launches the app. It never reads, types or stores anything. Keep it in a folder
only you can write to (the default for your user profile).

If a combination does nothing, another program may already own it. Try a different letter in the
script (`#!p::` means Win+Alt+P; change the `p`).

## What happens when it is already open

Pressing the shortcut again does **not** start a second copy. The new process notices the
running one, brings its window to the front, and exits. If the window was minimized, the vault
was locked when it was minimized, so you will see the unlock screen.

This matters for safety: two copies of the app on one vault would each save their own view of
the file, and the second save could discard the first one's changes. As a second line of
defence the app now refuses to save over a vault file that changed on disk since it was loaded,
and tells you to lock and unlock to reload (see DD-7 in
[DESIGN_DECISIONS.md](DESIGN_DECISIONS.md)).

## Tips

- Pin the app to the taskbar (right-click the running window's icon).
- Lock on minimize is on by default; `pm app --no-lock-on-minimize` turns it off.
- Auto-lock after idle still applies: `pm app --auto-lock 120` for two minutes.
