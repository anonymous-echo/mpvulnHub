> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI4MjkxNzY1NQ==&mid=2247486005&idx=1&sn=264eaaced170be759dbfc03828c82d65

#  【威胁情报】：Notepad++ 本地提权漏洞 | POC目前已公开  
稻草人  玄武盾网络技术实验室   2025-06-25 00:30  
  
“  
 对我们感兴趣的话就点个关注吧！**”**  
  
  
## 免责声明：本文仅供安全研究与学习之用，严禁用于非法用途，违者后果自负。  
  
## 漏洞背景与技术细节  
  
截至 2025 年 6 月 24 日，CVE-2025-49144 被认定为一个极为严重的安全漏洞，其影响范围涵盖 Notepad++ 的安装程序，具体涉及 v8.8.1 及更早版本。Notepad++ 作为一款在 Windows 系统中被广泛运用的免费开源源代码编辑器，深受众多用户青睐。  
  
  
经检测，该漏洞类型为 “未受控制的可执行文件 / 动态链接库搜索路径”（Uncontrolled EXE/DLL Search Path），亦被称作 “二进制植入”（Binary Planting），属于本地权限提升类漏洞。在计算机程序运行机制中，可执行文件在启动时，会按照特定规则搜索所需的动态链接库文件（DLL）。正常情况下，系统会优先在安全且指定的目录中进行查找，如系统文件夹（像 Windows 系统中的 C:\Windows\System32 等目录，其中存放着 kernel32.dll、user32.dll 等众多重要的动态链接库文件）。然而，当存在 “未受控制的可执行文件 / 动态链接库搜索路径” 这类漏洞时，恶意攻击者便有机会通过精心构造的方式，让程序在搜索 DLL 文件时，优先加载其植入的恶意 DLL。例如，攻击者可能会将恶意 DLL 放置在程序启动时默认搜索路径中的某个位置，而程序由于漏洞原因，未能遵循安全搜索机制，直接加载了该恶意 DLL，从而使得恶意代码得以执行。在本地权限提升方面，一旦恶意 DLL 被加载执行，攻击者就可能利用漏洞，突破原本用户所具有的权限限制，获取更高的系统权限。这就好比普通用户在系统中原本只有查看某些文件的权限，但攻击者利用此漏洞，使该用户能够获得修改甚至删除系统关键文件的权限，进而对系统的稳定性、安全性造成严重威胁。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/XoIcX2HtlUBabgm0LuQzXGLWMNbtxb1AcXiaDy69J6hmg2mvHfpsPMECvzrgbiczrCnsBZxclWVick4Y0Zic77fDZg/640?wx_fmt=jpeg&from=appmsg&wxfrom=13&tp=wxpic "")  
  
根据技术调查结果显示，该漏洞的根本成因在于 Notepad++ 安装程序在调用
```
regsvr32
```

  
组件时未采用绝对路径引用机制。具体而言，其底层实现逻辑中可能存在类似如下的代码调用形式：  
- **漏洞代码**  
：
```
ExecWait 'regsvr32 /u /s &#34;$INSTDIR\NppShell_01.dll&#34;'
```

  
这会导致安装程序从当前工作目录加载 
```
regsvr32.exe
```

  
，攻击者若事先在该目录放置了恶意可执行文件，系统将以 SYSTEM 权限执行该文件。  
  
修复版本 v8.8.2 修改了该行为，明确指定绝对路径，如：  
- **修复代码**  
：
```
ExecWait '$SYSDIR\regsvr32.exe /u /s &#34;$INSTDIR\NppShell_01.dll&#34;'
```

  
这样可以避免从当前工作目录加载恶意文件。  
  
  
## 攻击方法与影响  
  
攻击方法分为以下几个步骤：  
1. **准备阶段**  
：攻击者在目标系统当前工作目录中放置一个恶意的 
```
regsvr32.exe
```

  
 文件或其他可执行文件。  
  
1. **攻击向量**  
：用户运行 Notepad++ v8.8.1 的安装程序。  
  
1. **执行阶段**  
：安装程序调用 
```
regsvr32
```

  
 时，从当前工作目录加载恶意文件，并以 SYSTEM 权限执行。  
  
1. **结果**  
：攻击者获得对系统的完全控制权，可安装程序、修改数据或创建新账户  
  
该漏洞的严重性被评为高（High），CVSS v3 分数为 AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H，评分为 7.8/10。用户交互（UI:R）是触发条件之一，但攻击者只需诱导用户运行安装程序即可。  
## PoC 与公开信息  
  
目前已公开该漏洞的概念验证（PoC）材料，可供安全研究领域专业人员开展漏洞验证工作。相关 PoC 资源可通过以下链接获取，其中包含漏洞演示视频及核心验证代码。这一公开行为标志着该漏洞已引发安全业界的广泛关注，从风险评估角度来看，其潜在威胁等级已显著提升。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/XoIcX2HtlUBabgm0LuQzXGLWMNbtxb1AQgwde4H6q4p0qEMLWP4QYNLWK8vicDxXPBpTQeywVZV0ybs9Em1L15Q/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
![演示视频](https://mmbiz.qpic.cn/mmbiz_jpg/XoIcX2HtlUBabgm0LuQzXGLWMNbtxb1An8XfniczEUTxiaIApAZJc0gZhbicbicl6eibmcOZ2EJSQaibG37V6BcSA5ibQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
演示视频  

```
https://youtu.be/qCQlVllAfO0

```

  
**POC**  

```
https://github.com/notepad-plus-plus/notepad-plus-plus/security/advisories/GHSA-9vx8-v79m-6m24
https://drive.google.com/drive/folders/11yeUSWgqHvt4Bz5jO3ilRRfcpQZ6Gvpn

```

## 修复建议  
  
**1、所有 Notepad++ 用户请务必更新至 8.8.2 及以上版本**  
  
**2、下载渠道谨慎：强烈建议从 Notepad++ 官网、GitHub Releases 下载，不使用第三方镜像或链接。**  
  
**3、安装隔离建议：对于重要设备，将安装操作限于受控目录，避免与下载文件混杂。**  
  
**4、强化本地保护机制：结合用户权限控制、安装时 UAC 弹出提示等机制阻挡本地投毒路径。**  
  
**5、提升警惕：定期清理 Downloads 文件夹，不随意执行下载的 EXE 和 DLL；企业可结合 EDR 工具拦截异常加载行为。**  
  
此外，开发人员和系统管理员可参考以下建议：  
- **使用绝对路径**  
：确保所有可执行文件的调用使用绝对路径，避免从当前工作目录加载。  
  
- **数字签名验证**  
：实施文件数字签名验证，确保加载的文件来源可信。  
  
- **安全临时目录**  
：使用随机化的临时目录名称，减少攻击者植入恶意文件的可能性。  
  
## 相关漏洞与对比  
  
该漏洞与以下类似漏洞有一定关联：  
- CVE-2023-6401：涉及类似二进制植入问题。  
  
- CVE-2023-47452：特权提升漏洞。  
  
- CVE-2024-44346：相关软件中的类似问题。  
  
- Dell SupportAssist (DSA-2024-312)：涉及安装程序的安全性问题  
  
这些漏洞均强调了安装程序中未受控制搜索路径的潜在风险，值得注意。  
## 时间线与发布信息  
  
根据技术调查数据显示，该安全漏洞首次披露于 2025 年 5 月 5 日，美国国家漏洞数据库（NVD）于 2025 年 6 月 23 日完成相关变更记录的更新。公开情报表明，GitHub 安全咨询平台近期同步更新了漏洞详情，其技术文档中对漏洞原理、影响范围及潜在风险进行了系统性阐述：  

```
https://github.com/notepad-plus-plus/notepad-plus-plus/security/advisories/GHSA-9vx8-v79m-6m24

```

  
## 漏洞总结  
  
<table><thead><tr><th style="color: rgb(66, 75, 93);font-size: 14px;line-height: 1.5em;letter-spacing: 0em;text-align: left;font-weight: bold;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);height: auto;border-style: solid;border-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;padding: 5px 10px;min-width: 85px;"><strong style="color: rgb(66, 75, 93);font-weight: bold;background-attachment: scroll;background-clip: border-box;background-color: rgba(0, 0, 0, 0);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;margin-top: 0px;margin-bottom: 0px;margin-left: 0px;margin-right: 0px;padding-top: 0px;padding-bottom: 0px;padding-left: 0px;padding-right: 0px;border-top-style: none;border-bottom-style: none;border-left-style: none;border-right-style: none;border-top-width: 3px;border-bottom-width: 3px;border-left-width: 3px;border-right-width: 3px;border-top-color: rgba(0, 0, 0, 0.4);border-bottom-color: rgba(0, 0, 0, 0.4);border-left-color: rgba(0, 0, 0, 0.4);border-right-color: rgba(0, 0, 0, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><span leaf="">字段</span></strong></th><th style="color: rgb(66, 75, 93);font-size: 14px;line-height: 1.5em;letter-spacing: 0em;text-align: left;font-weight: bold;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);height: auto;border-style: solid;border-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;padding: 5px 10px;min-width: 85px;"><strong style="color: rgb(66, 75, 93);font-weight: bold;background-attachment: scroll;background-clip: border-box;background-color: rgba(0, 0, 0, 0);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;margin-top: 0px;margin-bottom: 0px;margin-left: 0px;margin-right: 0px;padding-top: 0px;padding-bottom: 0px;padding-left: 0px;padding-right: 0px;border-top-style: none;border-bottom-style: none;border-left-style: none;border-right-style: none;border-top-width: 3px;border-bottom-width: 3px;border-left-width: 3px;border-right-width: 3px;border-top-color: rgba(0, 0, 0, 0.4);border-bottom-color: rgba(0, 0, 0, 0.4);border-left-color: rgba(0, 0, 0, 0.4);border-right-color: rgba(0, 0, 0, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><span leaf="">详情</span></strong></th></tr></thead><tbody><tr style="color: rgb(66, 75, 93);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">CVE ID</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">CVE-2025-49144</span></section></td></tr><tr style="color: rgb(66, 75, 93);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">软件包</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">Notepad++ (Windows)</span></section></td></tr><tr style="color: rgb(66, 75, 93);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">受影响版本</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">v8.8.1 及更早</span></section></td></tr><tr style="color: rgb(66, 75, 93);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">修复版本</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">v8.8.2</span></section></td></tr><tr style="color: rgb(66, 75, 93);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">漏洞类型</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">未受控制 EXE/DLL 搜索路径 (Binary Planting)</span></section></td></tr><tr style="color: rgb(66, 75, 93);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">影响</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">本地特权提升至 NT AUTHORITY\SYSTEM</span></section></td></tr><tr style="color: rgb(66, 75, 93);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">发布日期</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">2025-05-05</span></section></td></tr><tr style="color: rgb(66, 75, 93);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">严重性</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">高</span></section></td></tr><tr style="color: rgb(66, 75, 93);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">CVSS v3 分数</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H, 评分为 7.8/10</span></section></td></tr><tr style="color: rgb(66, 75, 93);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">攻击方法</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">攻击者植入恶意文件，用户运行安装程序，加载恶意文件以 SYSTEM 权限执行</span></section></td></tr><tr style="color: rgb(66, 75, 93);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">PoC</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">公开</span></section></td></tr><tr style="color: rgb(66, 75, 93);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">类似漏洞</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">CVE-2023-6401, CVE-2023-47452, CVE-2024-44346, Dell DSA-2024-312</span></section></td></tr></tbody></table>  
  
  
为爱发电，创作不易，随手点个「推荐」吧！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/UM0M1icqlo0knIjq7rj7rsX0r4Rf2CDQylx0IjMfpPM93icE9AGx28bqwDRau5EkcWpK6WBAG5zGDS41wkfcvJiaA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
声明：  
技术文章均收集于互联网，仅作为本人学习、记录使用。  
侵权删  
！  
！  
！  
  
