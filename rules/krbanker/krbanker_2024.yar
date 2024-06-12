rule krbanker {
    meta:
        author = "Shaurya"
        date = "2024-06-12"
        description = "BlackMoon, win.krbanker malware as seen in 1.1.exe"
    strings:
        $sequence1 = { 55 8B EC 6A FF 68 30 3E 41 00 68 10 C6 40 00 64 } // seq 1: push ebp; mov ebp, esp; push 0xFFFFFFFF; push offset stru_413E30; push offset __except_handler3
        $sequence2 = { E8 48 15 00 00 85 C0 75 08 } // seq 2: call __mtinit; test eax, eax; jnz short loc_40AE2C
        $sequence3 = { 83 65 FC 00 E8 77 13 00 00 FF 15 38 30 41 00 A3 14 F2 55 00 } // seq 3: and [ebp+ms_exc.registration.TryLevel], 0; call __ioinit; call ds:GetCommandLineA; mov dword_55F214, eax
        $sequence4 = { 8B 65 E8 FF 75 E0 } // seq 4: mov esp, [ebp+ms_exc.old_esp]; push [ebp+Code]
        $strings1 = "BlackMoon RunTime Error:"
    condition:
        any of ($sequence1, $sequence2, $sequence3, $sequence4) or $strings1
}
