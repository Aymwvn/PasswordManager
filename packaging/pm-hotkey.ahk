#Requires AutoHotkey v2.0
#SingleInstance Force

; Win+Alt+P opens PasswordManager. If it is already running, the app just brings its
; window to the front (it never starts a second copy).
#!p:: {
    exe := A_ScriptDir "\..\dist\PasswordManager\PasswordManager.exe"
    if !FileExist(exe)
        exe := A_ScriptDir "\..\.venv\Scripts\pm-app.exe"
    if !FileExist(exe) {
        MsgBox('PasswordManager was not found. Install it first: pip install -e ".[app]"')
        return
    }
    Run('"' exe '"')
}
