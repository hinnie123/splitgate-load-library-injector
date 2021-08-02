# splitgate-load-library-injector
A loadlibrary injector for the game Splitgate that fully bypasses their EQU8 anti-cheat implementation.

# Information
The game Splitgate uses an anti-cheat solution called "EQU8".

"A lightweight client-side anti-cheat solution to protect the game from hackers and cheaters.
The anti-cheat can be implemented under 90 minutes, which is made possible through our simple engine-agnostic API and detailed step-by-step integration guide."

# Bypassing
I guess Splitgate developers might want to spend a little bit more than the 90 minutes on implementing EQU8.
Normally, most games use so called heartbeats to make sure the integrated anticheat is in fact running, before allowing
people to run the game, and join or be on any servers.

This bypass makes use of the fact that the game doesn't check heartbeats, by terminating the EQU8 process as soon as it starts.
By doing this, the game will effectively be running without any anticheat, and the game doesn't know it.
This allows us to easily do anything with the game that you want.

I've also left in a Splitgate queue bypass.