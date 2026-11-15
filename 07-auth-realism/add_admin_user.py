#!/usr/bin/env python3
"""Add the `admin` persona user (uid 1002) to the Cowrie fs.pickle.

Idempotent: does nothing if admin already exists. Creates a timestamped
backup (fs.pickle.pre07) before the first modification.

Run on the VPS host as root:  python3 add_admin_user.py
"""
import pickle
import sys
from datetime import datetime, timezone

PICKLE = "/opt/cowrie/data/fs.pickle"
BACKUP = "/opt/cowrie/data/fs.pickle.pre07"

ADMIN_UID = 1002
T_DIR, T_FILE = 1, 2
INSTALL = int(datetime(2025, 10, 21, 10, tzinfo=timezone.utc).timestamp())
RECENT = int(datetime(2026, 11, 14, 9, tzinfo=timezone.utc).timestamp())

BASHRC = """# ~/.bashrc: executed by bash(1) for non-login shells.
case $- in
    *i*) ;;
      *) return;;
esac
HISTCONTROL=ignoreboth
shopt -s histappend
HISTSIZE=1000
HISTFILESIZE=2000
shopt -s checkwinsize
if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"
    alias ls='ls --color=auto'
    alias grep='grep --color=auto'
fi
alias ll='ls -alF'
"""

PROFILE = """# ~/.profile: executed by the command interpreter for login shells.
if [ -n "$BASH_VERSION" ]; then
    if [ -f "$HOME/.bashrc" ]; then
\t. "$HOME/.bashrc"
    fi
fi
if [ -d "$HOME/bin" ] ; then
    PATH="$HOME/bin:$PATH"
fi
"""

HISTORY = """cd /var/www/html
ls -la
sudo systemctl status nginx
sudo tail -20 /var/log/nginx/error.log
scp -r /var/backups admin@10.0.0.16:/srv/incoming/
df -h
exit
"""


def f(name, uid, gid, content, mode=0o100644, mtime=INSTALL):
    if isinstance(content, str):
        content = content.encode()
    return [name, T_FILE, uid, gid, len(content), mode, mtime, content, None, None]


def d(name, uid, gid, mode=0o40755, mtime=INSTALL, children=None):
    return [name, T_DIR, uid, gid, 4096, mode, mtime, children if children is not None else [], None, None]


def find(root, path):
    node = root
    if path in ("", "/"):
        return node
    for part in [p for p in path.split("/") if p]:
        node = next((c for c in node[7] if c[0] == part), None)
        if node is None:
            return None
    return node


def main():
    root = pickle.load(open(PICKLE, "rb"))
    passwd = find(root, "/etc/passwd")
    if b"\nadmin:" in passwd[7] or passwd[7].startswith(b"admin:"):
        print("admin already present in pickle — nothing to do")
        return 0

    import shutil
    shutil.copy2(PICKLE, BACKUP)
    print(f"backup written: {BACKUP}")

    # /etc/passwd, /etc/shadow, /etc/group, /etc/gshadow
    passwd[7] += f"admin:x:{ADMIN_UID}:{ADMIN_UID}:Admin,,,:/home/admin:/bin/bash\n".encode()
    passwd[4] = len(passwd[7])

    shadow = find(root, "/etc/shadow")
    shadow[7] += b"admin:$6$wQ9zLm4x$J8vN3qW7tY2uI5oP1aS4dF6gH8jK0lZ2xC4vB6nM8qW0eR2tY4uI6oP8aS0dF2gH4jK6l8zX1c:19980:0:99999:7:::\n"
    shadow[4] = len(shadow[7])

    group = find(root, "/etc/group")
    group[7] += f"admin:x:{ADMIN_UID}:\n".encode()
    group[4] = len(group[7])

    gshadow = find(root, "/etc/gshadow")
    gshadow[7] += b"admin:!::\n"
    gshadow[4] = len(gshadow[7])

    # /home/admin
    home = find(root, "/home")
    home[7] = [c for c in home[7] if c[0] != "admin"]
    home[7].append(d("admin", ADMIN_UID, ADMIN_UID, children=[
        f(".bashrc", ADMIN_UID, ADMIN_UID, BASHRC),
        f(".profile", ADMIN_UID, ADMIN_UID, PROFILE),
        f(".bash_history", ADMIN_UID, ADMIN_UID, HISTORY, mode=0o100600, mtime=RECENT),
    ]))

    pickle.dump(root, open(PICKLE, "wb"), protocol=2)
    print("admin (uid 1002) added to pickle — restart cowrie to apply")
    return 0


if __name__ == "__main__":
    sys.exit(main())
