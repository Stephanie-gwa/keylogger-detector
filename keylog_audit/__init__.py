"""
keylog_audit — a defensive, READ-ONLY tool that looks for documented,
OS-level indicators associated with keylogging activity on YOUR OWN
computer, and explains exactly why each process was flagged.

What this project is NOT:
  - It does not log, capture, or record any keystroke, ever.
  - It does not install any keyboard hook, driver, or input listener.
  - It does not claim to detect every possible keylogger. Many real
    techniques (kernel-mode drivers, hardware keyloggers, browser
    extensions, techniques that leave no OS-visible trace this project
    checks) are NOT covered — see README "Limitations".

Every check here reads process metadata and OS-documented permission/
persistence locations that are already exposed to a normal user account
for legitimate system-administration purposes (Task Manager, Activity
Monitor, ps/proc, autostart settings) — nothing here requires or uses
elevated access beyond what the current user already has, and nothing
here modifies anything on the system.
"""
__version__ = "1.0.0"
