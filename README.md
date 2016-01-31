ttyrider is a program I wrote while working at iSEC Partners/NCC Group that
uses ptrace to attach to a process and mirror its output and inject input.

see documentation/writeup for a more detailed explanation of how it works

It's intented uses are:

1) After rooting a box you see a user ssh'd into another box. You want to
immediately get access to that other box without keylogging or backdooring ssh
and waiting around for them to ssh again. As far as I know the best current
tool for that is reptyr, but it disconnects ssh from it's original tty so the
user will be suspicious. ttyrider leaves the user's terminal intact and does
basic output-hiding so that the attacker can run commands and see their output
without showing up in the user's terminal.

![demo](documentation/ssh_demo.gif)

2) After hacking a user's account you see they've run sudo or su, and you want
to immediately get root without keylogging or backdooring sudo and su and
waiting for them to sudo or su again. You can use ttyrider on the parent of
sudo or su to inject keystrokes on the tty to run commands as root, although
you won't be able to see the output. I don't know of any existing tool that
works for this? And I think Ubuntu is the only common distro that sets
/proc/sys/kernel/yama/ptrace_scope to 1 by default (which stops this)?

![demo](documentation/su_demo.gif)
