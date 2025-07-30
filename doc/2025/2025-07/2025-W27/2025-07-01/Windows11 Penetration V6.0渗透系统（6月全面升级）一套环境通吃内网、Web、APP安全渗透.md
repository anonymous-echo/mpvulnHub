> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247492883&idx=1&sn=ebc603921afcded169d999fd46f117ab

#  Windows11 Penetration V6.0渗透系统（6月全面升级）一套环境通吃内网、Web、APP安全渗透  
makoto56  渗透安全HackTwo   2025-06-30 16:01  
  
0x01 工具介绍  
  
  
「Windows11 Penetration Suite Toolkit v6.0」  
  
 是基于 **Windows 11 24H2 x64**  
 深度定制的渗透测试集成环境，专为红队蓝队对抗设计。本版本全面适配 ，集成 **WSL2 Kali 2025.1**  
 双系统联动，工具链覆盖漏洞分析、漏洞利用、内网渗透、免杀对抗等全场景，所有组件均经虚拟化隔离与性能优化，助力渗透测试。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5hHSdBXqBIe35jdG0A1f9rwUiax5OnP9dTOLiakly1CsNER2gWolhibhiafKuL8K91ZnbQZNdibodm9Cw/640?wx_fmt=png&from=appmsg "")  
  
  
**注意：**  
现在只对常读和星标的公众号才展示大图推送，建议大家把  
**渗透安全HackTwo**  
"**设为****星标⭐️**  
"  
**否****则可能就看不到了啦！**  
  
**下载地址在末尾#渗透安全HackTwo**  
  
0x02   
功能简介  
  
  
系统简介：  
1. **基于 Windows11 Workstation 24H2 x64 原版镜像制作(理论不支持 ARM 设备)**  
1. **完整安装 WSL2 Kali Linux 2025.1;**  
- **注: 物理主机须支持 CPU 虚拟化功能, 否则 WSL Kali 可能无法使用。**  
- **开启 VMware - 虚拟机设置 - 处理器 - 虚拟化引擎:**  
- **虚拟化 Intel VT-x/EPT 或 AMD-V/RVI**  
- **虚拟化 CPU 性能计数器**  
- **虚拟化 IOMMU(IO 内存管理单元)**  
1. **精简系统自带软件, 美化字体及部分图标, 适度优化;**  
- **推荐运行环境:**  
- **VMware: 17.x(建议视情分配图形内存)**  
- **运行内存: 8 GB**  
- **固态硬盘: 300 GB**  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5hHSdBXqBIe35jdG0A1f9rw8w6GmT46vaqCvINrxOTepXP21XskLr8kwQ1fqyXsahBxPbJDdE23Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5hHSdBXqBIe35jdG0A1f9ryZG9JRfOlFVTRr1qhz62zgs7fN6pkepyjFIXcKSLJIzEIAX0VrJib6A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5hHSdBXqBIe35jdG0A1f9r4WW8FH0hAW04iaEkXj4tvsUbic7C0rtqOtDLO0IbS1KX1la8LlsQ026g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5hHSdBXqBIe35jdG0A1f9raUhrEEUDmglaWfHE50np148Lh9AgDzHnEFmetZU3wv99oIhiazORKwA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5hHSdBXqBIe35jdG0A1f9r3WI0anXpAnLLu8oJv8ZEJJfFfX7U4CO2JkDOwJ1FVbmj6pNhJW9AbA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5hHSdBXqBIe35jdG0A1f9rTkM5cuMVpkUbiavxgcXsBgMDCkoSqoCqSrHF7ysFkibj7WO0a0630NPg/640?wx_fmt=png&from=appmsg "")  
  
## 🖥️ 软件及工具介绍:  
## [+] AI工具 (C:\Penetration\AiTools) :  
  
1. **CherryStudio: AI 资源聚合工具 v1.3.12**  
1. **Cursor: AI 代码编辑器 v0.50.5**  
1. **腾讯 IMA 知识库: v1.72**  
1. **Ai PPT**  
1. **ChatGPT**  
1. **DeepSeek**  
1. **Genspark**  
1. **Google Gemini**  
1. **Kimi**  
1. **PentestGPT**  
1. **Venice**  
1. **即梦 AI**  
  
### [+] 安卓工具 (C:\Penetration\AndroidTools):  
  
1. **AdbDriver: ADB 驱动 v1.0.31**  
1. **AndroidHelper: APK 逆向工具 v2.2**  
1. **AndroidKiller: APK 综合工具 v1.3.1.0**  
1. **Apk2url: APK 信息提取工具 v1.2**  
1. **APKDeepLens: APK 扫描工具 v1.0**  
1. **Apkinfo: APK 分析工具 v2.0.2**  
1. **Apkleaks: APK 扫描工具 v2.6.3**  
1. **ApkScan-PKID: APK 查壳工具 v1.0**  
1. **Apktool: APK 反编译工具 v2.11.1**  
1. **ApkToolPlus: APK 反编译分析工具**  
1. **AppMessenger: APK 分析工具 v4.6.3**  
1. **BlueStacks: 蓝叠模拟器(国际版) v5**  
- **已安装**  
- **Debug Proxy**  
- **Dev Tools**  
- **Http Canary**  
- **MT Manager**  
- **Net Capture**  
- **Packet Capture**  
- **Terminal Emulator**  
1. **BytecodeViewer: 字节码查看工具 v2.13.1**  
1. **Dextools: Dex 打包工具 v2.4**  
1. **Jadx-GUI: 反编译工具 v1.5.1**  
1. **JavaDecompiler: 字节码查看工具 v1.6.6**  
1. **SuperJadx: 反编译工具 v10.0**  
1. **Yaazhini: APK 漏洞扫描工具 v2.0.2**  
  
### [+] 免杀工具 (C:\Penetration\AntivirusTools):  
  
1. **AVevasion: v20231208**  
1. **AvEvasionCraftOnline: v1.2**  
1. **Aycvxz: 分离免杀工具 v1.4.2**  
1. **BypassAV: v1.6**  
1. **Charlotte: v1.1**  
1. **Invoke-Obfuscation: v1.0**  
1. **Invoke-Obfuscation-Bypass: v1.0**  
1. **LoaderFly: v2.0**  
1. **MaLoader: 基于 Tauri + Rust 免杀马生成工具 v1.1**  
1. **RingQ: 后渗透免杀工具**  
1. **Sandboxie: 沙盒工具 v5.70.12**  
1. **SGN: 编码工具 v2.0.1**  
1. **S-inject: 注入免杀工具 v2.2**  
1. **VMProtect: v3.8.4(注册版)**  
1. **VProtect: 加壳工具 v2.1.0**  
  
### [+] 审计工具 (C:\Penetration\AuditTools):  
  
1. **Fortify: v24.4.0(注册版)**  
1. **PHPAuthScanner: PHP 鉴权代码扫描器 v1.1**  
1. **Seay: Seay 源代码审计系统 v2.1**  
1. **SeayDzend**  
  
### [+] 连接工具 (C:\Penetration\ConnectTools):  
  
1. **1Remote v1.2.0**  
1. **Anydesk v9.5.4**  
1. **AweSun: 向日葵 v15.8.4**  
1. **Filezilla v3.69.0**  
1. **Finalshell v4.5.12**  
1. **PuTTY v0.83**  
1. **Teamviewer v15.66.5**  
1. **ToDesk v4.7.7.2**  
1. **WinSCP v6.5.1**  
1. **Xftp v8.0(教育版)**  
1. **Xshell v8.0(教育版)**  
  
### [+] 破解工具 (C:\Penetration\CrackTools):  
  
1. **Advanced Archive Password Recovery: 压缩包密码破解工具**  
1. **Advanced Office Password Recovery: Office 密码破解工具**  
1. **Advanced PDF Password Recovery: PDF 密码破解工具**  
1. **DecryptPassword**  
- **文件夹下集成下列工具**  
- **FinalShellPassMassDecode v1.0**  
- **Firefox_decrypt v1.1.1**  
- **Hack-browser-data-windows v0.4.6**  
- **PassGet**  
- **SharpDecryptPwd v2.3.0**  
- **TeamView_get_Password v1.0**  
- **Teamviewer-dumper v1.0**  
- **VcenterExsi_PwdDecrypt v1.0**  
1. **DecryptTools: 加解密综合利用工具 v3.1**  
1. **e0e1-config: 密码抓取解密工具 v1.30**  
1. **Hashcat: 密码破解工具 v6.2.6**  
1. **Hydra: 密码破解工具 v9.1**  
1. **John: 密码破解工具 v1.9.0**  
1. **Johnny: John 图形化版本 v2.2**  
1. **Kraken: 密码暴力破解工具**  
1. **MD5Crack: MD5碰撞工具 v1.0**  
1. **Web Browser Pass View: 浏览器密码抓取工具**  
1. **SNETCracker: 超级弱口令检测工具 v1.0**  
1. **WebshellCrack: K8 一句话木马密码破解工具**  
1. **Week-Passwd: 弱口令检测工具 V2.0**  
  
### [+] 夺旗工具 (C:\Penetration\CTFTools):  
  
1. **ASCII: ASCII 码转换工具**  
1. **Audacity: 音频工具**  
1. **BehinderDecode: 冰蝎流量解码工具**  
1. **BerylEnigma: 密码学工具 v1.15.0**  
1. **Binwalk: 文件分析工具 v3.1.0**  
1. **Blind_Watermark: 盲水印工具 v0.2.1**  
1. **CaptfEncoder: 密码学工具 V2**  
1. **Ciphey: 全自动解密工具 V5.14.0**  
1. **Converter: 编码转换工具**  
1. **CRCCalculator: CRC 计算工具**  
1. **CTFCrack: CTF 工具框架 v2.1**  
1. **CTFCrackTools: CTF 工具框架 v4.0.7**  
1. **CTFEditor: 随波逐流 CTF 工具**  
1. **CTFTools: 密码学工具 v1.3.7**  
1. **CyberChef: 密码学工具 v10.19.4**  
1. **DesTool: DES 加解密工具**  
1. **FindFlag: Flag 查找工具**  
1. **Foremost: 分离工具**  
1. **GifTools: GIF 图片工具**  
1. **GNUplot: 数学绘图工具 v6.0.2**  
1. **JPHS: 图片隐写工具**  
1. **LSB-Steganography: 图片隐写工具**  
1. **MossTool: 摩斯密码转换工具**  
1. **MP3Steno: 音频隐写工具**  
1. **Outguess: 隐写工具**  
1. **PcapTool: 流量分析工具**  
1. **PixelJihad: 图片隐写工具**  
1. **PixRecovery: 图片修复工具**  
1. **PNGCalculator: PNG 图片计算工具**  
1. **PNGCheck: PNG 图片计算工具**  
1. **PNGDebugger: PNG 图片计算工具**  
1. **PYGTools: 飘云阁密码学工具**  
1. **QRCode: 二维码批量扫描工具**  
1. **QRResearch: 二维码解析工具**  
1. **Regular: 正则工具**  
1. **RSATool: RSA 计算工具**  
1. **SM4: SM4 加解密工具**  
1. **Stegdetect: 隐写工具**  
1. **Steghide: 隐写工具**  
1. **Stegsolve: 隐写工具**  
1. **TaowaTool: CTF 工具框架**  
1. **TweakPNG: PNG 调整工具**  
1. **Ulead GIF Animator: GIF 图片工具**  
1. **wbStego: 图片隐写工具**  
1. **WinDecrypto: 密码学工具**  
1. **WinHex: 十六进制编辑工具**  
1. **Xiaokui: 小葵编码工具**  
1. **ZZYQR: 二维码解析工具**  
  
### [+] 数据库工具 :  
  
1. **Another Redis Desktop Manager: Redis 客户端 v1.7.1**  
1. **DatabaseTools: 数据库综合利用工具 v1.2**  
1. **HeidiSQL: 数据库管理工具 v12.10**  
1. **MariaDB: Mysql 数据库 v11.7**  
- **username: root**  
- **password: sqladmin**  
- **如需使用, 请先运行“开启服务”快捷方式。**  
1. **Multiple Database Utilization Tools: 数据库综合利用工具 v2.1.1**  
1. **Multiple Database Utilization Tools - Extend: MDUT 增强版 v1.2.0**  
1. **Navicat: 数据库管理工具(注册版) v17.1.12**  
1. **Neo4j v1.6.2**  
- **username: root**  
- **password: sqladmin**  
1. **Oracle 23ai Free**  
- **username: sys**  
- **password: sqladmin**  
- **如需使用, 请先运行“开启服务”快捷方式。**  
1. **OracleShell: Oracle 数据库利用工具 v1.0**  
1. **OSS-Browser: 数据库管理工具 v1.18.0**  
1. **PostgreUtil: Postgresql 数据库利用工具 v1.0**  
1. **Redis: Redis 客户端(Kali)**  
1. **SharpsqlTools: sqlServer 利用工具 v41**  
1. **sqLite: sqLite 客户端 v3.13.1**  
1. **sqlKnife: sqlServer 利用工具 v1.2**  
1. **Sqlmap: 数据库利用工具 v1.9**  
1. **Sqlmap Studio: 配置 SQLMap 命令**  
1. **SqlmapXPlus: Sqlmap 二开版 v1.6**  
1. **sqlServer 2022: 专业版**  
- **username: sa**  
- **password: sqladmin**  
- **如需使用, 请先运行“开启服务”快捷方式。**  
1. **sqlServer Management Studio 21: sqlServer 管理工具**  
1. **sqlTools: sqlServer 利用工具 v2.0**  
1. **ssqlinjection: 超级注入工具 v1.0**  
1. **Sylas: 数据库利用工具**  
1. **TinyRDM: Redis 客户端 v1.2.3**  
1. **Toad for Oracle: Oracle 客户端 v16.2.98**  
  
### [+] 字典工具 (C:\Penetration\DictionaryTools):  
  
1. **UserNameDictTools: v0.36**  
1. **Social Engineering Dictionary Generator: 社工字典生成工具 v1.2.0**  
1. **木头字典生成工具**  
1. **品轩字典生成工具**  
1. **Pentestdicts**  
  
### [+] 磁盘工具 (C:\Penetration\DiskTools):  
  
1. **傲梅分区助手 v10.8.1**  
1. **傲梅系统备份 v7.5.0**  
1. **Disk Drill: 数据恢复工具(注册版) v5.7.917.0**  
1. **DiskGenius: v5.6.1.1580(注册版)**  
1. **SSDFresh: 磁盘整理工具 v2025.14.0**  
  
### [+] 编辑工具 (C:\Penetration\EditTools):  
  
1. **010Editor: 十六进制编辑工具(注册版) v13.0.1**  
1. **AnyTXT: 文本搜索工具 v13.2034**  
1. **BeyondCompare: 文件对比工具 v5.0.7**  
1. **JsonViewer: Json 查看编辑工具 v3.1**  
1. **Microsoft VS Code v1.100.2**  
1. **myBase: 个人数据库编辑工具(注册版) v7.3**  
1. **Notepad++: 编辑工具 v8.4.4**  
1. **PSTConverter: Outlook PST 邮件转换工具**  
1. **SharpSword: Word 命令行查看工具**  
1. **Sublime Text: 编辑工具(注册版) v4.4192**  
1. **ToolsFx: 密码学工具 v1.18.0**  
1. **Typora: MarkDown 编辑工具(注册版) v1.9.5**  
1. **UltraEdit: 编辑工具 v2024.3**  
1. **WinHex: 16进制编辑工具(注册版) v21.4**  
1. **XMind: 思维导图工具(注册版) v25.04**  
  
### [+] 漏洞工具 (C:\Penetration\ExploitTools):  
  
1. **漏洞利用工具**  
- **Aakian-FaCai: VUE 漏洞扫描工具 v1.0.0**  
- **AliyunAKTools: 阿里云利用工具 v1.3**  
- **AptTools: 综合漏洞利用工具**  
- **AuxTools: 漏洞综合利用工具 v5.5.3**  
- **EquationToolsGUI: 方程式工具包图形界面版 v0.48**  
- **ExpDemo: 综合漏洞利用工具 v1.9**  
- **Exp-Tools: 综合漏洞利用工具 v1.3.1**  
- **HeapdumpTool: 敏感信息提取工具**  
- **HVVExploitApply: 综合漏洞利用工具 v1.5**  
- **Hyacinth: 综合漏洞利用工具 v2.0**  
- **IWannaGetAll: OA 漏洞利用工具 v1.4.0**  
- **JavaChains: Java Payload 综合生成与利用平台 v1.4.1**  
- **JDumpSpider: 敏感信息提取工具 v20250409T071858**  
- **JNDI-Exploit: JNDI 注入测试工具 v1.4**  
- **JNDI-Injection-Exploit: JNDI 注入测试工具 v1.0**  
- **JNDI-Injection-Exploit-Plus: JNDI 注入测试工具 v2.5**  
- **Linux Exploit Suggester: Linux 提权工具 v1.1**  
- **LiqunKit: 综合漏洞利用工具 v1.6.2**  
- **List Cloud: 云攻击资产梳理工具 v1.1.0**  
- **Moriarty: Windows 提权工具 v1.2**  
- **MYExploit: 综合漏洞利用工具 v2.0.5**  
- **Nuclei: 漏洞扫描利用工具 v3.4.4**  
- **Poc2jar: 综合漏洞利用工具 v0.6.8**  
- **PotatoTool: 综合利用工具 v2.5**  
- **R-Knife: 综合漏洞利用工具 v1.2**  
- **SearchSploit: (Kali)**  
- **SuperXray: Xray 图形化版本**  
- **TheLostWorld: OA 漏洞利用工具 v1.1**  
- **Unauthorized: 未授权漏洞检测工具**  
- **Windows Exploit Suggester - NG: Windows 提权工具**  
- **Wiki: 零组文档库 & 漏洞文档库**  
- **Xray: 漏洞扫描利用工具 v2.0**  
- **Ysoserial: Java 反序列化利用工具 v0.0.6**  
1. **EXP & POC : C:\Penetration\ExploitTools\Vulnerability**  
- **漏洞库综合了下列项目, 更多漏洞 EXP & POC 请善用 Everything 搜索:**  
- **CMS-Hunter**  
- **expHub**  
- **Middleware-Vulnerability-Detection**  
- **System-Vulnerability**  
- **Vulnerability**  
  
### [+] 取证工具 (C:\Penetration\ForensicsTools):  
  
1. **AlternateStreamView: NTFS 数据流工具 v1.58**  
1. **AutoSpy: v4.22.1**  
1. **EvtxECmd: Windows 日志分析工具 v1.5.2.0**  
1. **FireKylin: 系统痕迹采集工具 v1.4.0**  
1. **GetInfo: 应急响应信息采集 v1.2.1**  
1. **Get Win info**  
1. **Gather: Linux服务器信息收集脚本 v1.0**  
1. **GhostWolf: 内存敏感信息提取工具 v1.1**  
1. **Hawkeye: 应急响应工具 v3.0**  
1. **Hema: 河马 Webshell 查杀 v1.8.2**  
1. **KunWu: 昆吾 Webshell 查杀 v0.1.0**  
1. **Log Parser: Windows 日志工具 v2.2**  
1. **Log Parser Lizard: LogParser 图形化工具 v8.7**  
1. **Log Parser Studio: LogParser 图形化工具 v3.0**  
1. **LovelyMem: 综合取证工具 v0.95**  
1. **Magnet AXIOM: 综合取证工具 v8.4**  
1. **MemProcFS: 内存取证工具 v5.14**  
1. **NTFSStreamsEditor: NTFS 数据流工具 v2.0.2**  
1. **NTPWEdit: SAM 文件编辑工具 v0.5**  
1. **oletools: OLE 文件分析工具 v0.60.2**  
1. **QEMU: 镜像分析工具 v20250422**  
1. **RegistryExplorer: Windows 注册表分析工具 v2.1.0**  
1. **Volatility2: v2.6.1**  
1. **Volatility3: v2.26.0**  
1. **WindowsBaselineAssistant: Windows 安全基线加固助手 v1.2.3**  
1. **WindowsLogsAnalysis: 日志分析工具 v1.0**  
1. **WinPmem: Windows 内存取证工具 v4.0**  
1. **WxDump: 微信取证工具 v1.4.1**  
  
### [+] 内网工具 (C:\Penetration\IntranetTools):  
  
1. **3Gstudent: 三好学生脚本**  
- **Homework-of-C-Language**  
- **Homework-of-C-Sharp**  
- **Homework-of-Go**  
- **Homework-of-Powershell**  
- **Homework-of-Python**  
1. **AddUser: 添加用户工具**  
- **文件夹下集成下列工具**  
- **bypass**  
- **bypass360**  
- **CreateHiddenAccount**  
- **hidecount**  
- **Suborner**  
- **vbs**  
1. **ADExplore: LDAP 工具 v1.52**  
1. **ADExplorerSnapshot: LDAP 工具 v1.0**  
1. **ADinfo: 内网信息搜集工具 v20220916**  
1. **BloodHound: 域渗透分析工具 v7.4.0**  
- **username: admin**  
- **password: Bloodhoundpassword@2025**  
- **如需使用, 请先运行“开启服务”快捷方式。**  
1. **BloudyAD: 域渗透利用工具 v2.1.18**  
1. **CrackMapExec: 内网综合利用工具 v5.4.0**  
1. **Cube: 内网密码爆破漏扫工具 v1.2.9**  
1. **DomainInfoFind: 获取域内机器的桌面文件 v1.0**  
1. **DomainTools: 域渗透综合利用工具 v1.0**  
1. **EarthWorm: 内网穿透工具 v1.2**  
1. **Evil-WinRM: WinRM 利用工具 v3.7**  
1. **FScan: 内网扫描工具 v2.0.1**  
1. **GoExec : Windows 远程执行多功能工具 v0.1.2**  
1. **GoToHTTP: 远控工具 v10.2**  
1. **HackerPermKeeper: 权限维持工具 v7.0**  
1. **Hoaxshell: 远控工具**  
1. **imPacket: 内网协议工具**  
- **文件夹下集成下列工具**  
- **imPacket-python: v0.13.0**  
- **impacket-windows v0.9.17**  
- **wmiexec-pro v0.3**  
1. **Kerbrute: 域枚举爆破工具 v1.0.3**  
1. **Ladon: 内网综合利用工具 v12.4**  
1. **LdapAdmin: LDAP 工具 v1.8.3**  
1. **LDAPDomainDump: LDAP 工具 v0.10.0**  
1. **Mimikatz: 密码抓取工具**  
- **文件夹下集成下列工具**  
- **CallBackDump**  
- **DumpHash**  
- **GoSecretsDump: v0.3.1**  
- **HKLM**  
- **Kekeo: v2.2.0**  
- **LaZagne: v2.4.7**  
- **Mimipenguin: v2.0**  
- **MultiDump**  
- **NTDSDumpEx: v0.3**  
- **Procdump: v11.0**  
- **Pwdump**  
- **Quarkspwdump**  
1. **Moonwalk: Linux 痕迹恢复工具**  
1. **Nacs: 内网扫描工具 v0.0.4**  
1. **NetSpy: 内网网段探测工具 v0.0.5**  
1. **OpenRDP: 开启远程桌面工具**  
1. **PEASS-ng: Linux 权限提升工具 v20250601**  
1. **Platypus 反向 shell 工具 v1.5.0**  
1. **PSTools: 微软 psexec 工具 v2.5.1**  
1. **PyStinger: 流量代理工具 v1.6**  
1. **Qscan: 内网扫描工具 v1.8**  
1. **Railgun: 内网渗透综合利用工具 v2.0.3**  
1. **RedPersist: 权限持久化工具 v1.0**  
1. **SearchAll: 内网信息收集工具 v3.5.11**  
1. **ScheduleRunner: 计划任务利用工具 v1.3**  
1. **SharpTools:**  
- **文件夹下集成下列工具**  
- **CSharp_EventLog: 日志分析工具 v1.1**  
- **ListRDPConnections: 远程桌面连接记录枚举工具 v0.0.3**  
- **SharpAdiDnsDump: 域 DNS 枚举工具**  
- **SharpEventLog: 日志分析工具**  
- **SharpHide: 创建隐藏注册表运行键**  
- **SharpHound: 域渗透分析工具 v2.6.6**  
- **SharpNetCheck: 出网探测工具**  
- **SharpRDPLog: 远程桌面连接记录枚举工具**  
- **SharpToken: 令牌窃取工具 v1.2**  
1. **Traitor: Linux 提权工具 v0.0.14**  
1. **WMIHacker: WMI 利用工具 v0.6**  
1. **Yasso: 内网渗透综合利用工具 v0.06**  
  
### [+] 影音图像 (C:\Penetration\MediaTools):  
  
1. **Adobe Acrobat DC 2025: PDF 编辑工具(注册版)**  
1. **Adobe Photoshop 2025**  
1. **Bandicam: 屏幕录像工具(注册版) v8.1**  
1. **FormatFactory: 格式工厂(注册版) v5.20**  
1. **Goldwave: 音频编辑工具 v7.0.2**  
1. **Honeyview: 图片查看工具 v7.17**  
1. **K-Lite Codec Pack: 视频解码库 v1895**  
1. **PotPlayer: 播放器 v1.7**  
1. **Snipaste: 截图工具 v2.10.6**  
  
### [+] 网络工具 (C:\Penetration\NetworkTools):  
  
1. **Chrome: 136.0.7103.114 绿色修改版**  
- **集成插件**  
- **Adblock: 广告拦截工具**  
- **Adobe Acrobat: PDF 编辑**  
- **Charset: 修改网页编码工具**  
- **Chrome清理大师: 清理工具**  
- **CrapApi: Http 接口调试插件**  
- **EditThisCookie: cookie编辑工具**  
- **FindSomething: 敏感文件搜集工具**  
- **Hack-Tools: 红队综合小工具**  
- **Hackbar**  
- **Imagus: 图片预览工具**  
- **Infinity: 标签页工具**  
- **IP address and domain inf: ip & domain 探测工具**  
- **IP Whois & Flags Chrome & Websites Rating: whois 探测工具**  
- **Neater bookmarks: 书签管理工具**  
- **Onetab: 标签管理工具**  
- **OWASP Penetration Testing Kit: 浏览器渗透测试工具**  
- **Proxy switchyomega: 代理切换工具**  
- **Shodan: 端口探测工具**  
- **Supercopy: 超级复制**  
- **User-Agent Switcher: 浏览头切换工具**  
- **Wappalyzer: 网页技术分析工具**  
- **WebSocket Test Client: websocket工具**  
- **Whatruns: 网页技术分析工具**  
- **XSS辅助工具**  
- **Yet Another Drag and Go FIX: 链接拖拽工具**  
- **图片另存为JPG/PNG/WebP**  
- **Toolbox 常用工具**  
- **篡改猴**  
- **github-chinese**  
- **草料二维码**  
  
### [+] 办公工具 (C:\Penetration\OfficeTools):  
  
1. **Office: 2024 专业增强版**  
- **Word 2024**  
- **Excel 2024**  
- **Powerpoint 2024**  
- **Access 2024**  
- **Onenote 2024**  
- **Outlook 2024**  
1. **WPS: 2023 专业增强版**  
  
### [+] 编程工具 (C:\Penetration\ProgramTools):  
  
1. **Go: v1.24.3**  
- **修改源为阿里云**  
1. **Java:**  
- **jdk8: 绿色版, 如有软件需要 jdk8 环境运行可直接调用/jdk1.8.0/bin/java.exe即可。**  
- **jdk21: 安装版, 已配置环境变量, 系统默认调用 jdk21。**  
1. **JetBrains: 2025.1(注册版)**  
- **CLion 2025**  
- **DataGrip 2025**  
- **GoLand 2025**  
- **IntelliJ IDEA 2025**  
- **PhpStorm 2025**  
- **PyCharm 2025**  
- **Rider 2025**  
- **RubyMine 2025**  
- **RustRover 2025**  
- **WebStorm 2025**  
- **已禁用自动更新, 专业版激活至2026年9月, 破解补丁到期后会循环激活, 理论上无需手动操作。如遇到激活状态失效, 请按教程手动运行/JetBrains/#Crack# 目录下的破解脚本。**  
1. **Maven: Windows & WSL Kali 同步安装 v3.9.9**  
1. **MinGW64: v15.1.0**  
1. **Nim: v2.2.4**  
1. **Node.js: v22.16.0**  
1. **Python:**  
- **修改源为阿里云**  
- **python2: 安装包形式安装, python2 命令启动(python2 test.py)**  
- **python3: Microsoft Store 直装, python 或 python3 命令启动(python test.py / python3 test.py)**  
- **使用 pip 命令调用 python3 pip**  
- **由于一些比较老的项目不兼容 python3.13 新版本的 pip 库, 且 Windows 共存不同版本的 python3 容易产生环境变量冲突问题, 所以在 WSL Kali 中同时安装了python2、python3.8、python3.13 三个版本。**  
- **为降低不同项目间依赖库的冲突问题, 本镜像所有 python3 工具的 pip 依赖库均以虚拟环境形式安装 (python3 -m venv) 在项目根目录下 (Windows 为 “win” 文件夹, WSL Kali 为“kali” 文件夹)。使用前需要先激活对应的虚拟环境, 否则会报错缺少运行库。**  
- **本镜像所有 python 项目均配备了 start.bat 快速启动脚本, 会根据项目需求调用不同版本的 python 并自动激活对应的虚拟环境, 方便一键使用。如果您需要手动运行, 请确保先激活对应的虚拟环境。**  
1. **Rust: v1.87.0**  
- **修改软件源为中科大**  
1. **TDM-GCC: v10.3.0**  
1. **Microsoft Visual Studio 2022: 社区版**  
  
### [+] 逆向工具 (C:\Penetration\ReverseTools):  
  
1. **DetectItEasy: 查壳工具 v3.10**  
1. **dnSpy: .Net 逆向工具 v6.1.8**  
1. **exeScope: exe 编辑工具 v6.50**  
1. **Ghidra: 逆向工具 v11.3.2**  
1. **GhostExplore: GHO 文件编辑工具 v12.0**  
1. **GreenHelper: 绿化工具 v1.4**  
1. **HashTool: Hash 计算工具 v1.4.0**  
1. **IDAPro: v9.1(注册版)**  
1. **ILSpy: .Net 逆向工具 v9.1.0**  
1. **OllyDebug: 吾爱破解修复增强版 v1.10**  
1. **PeiD: 查壳工具 v0.95**  
1. **SignTool: 签名工具 v1.0**  
1. **UPX: 加壳工具 v3.95**  
1. **x64Debug: 调试工具 v2025**  
  
### [+] 扫描工具 (C:\Penetration\ScanTools):  
  
1. **Acunetix: v25.1.250204093(注册版)**  
- **username: admin@awvs.com**  
- **password: Admin@awvs.com**  
- **如需使用, 请先运行“开启服务”快捷方式。**  
1. **AppScan: v10.8.0(注册版)**  
1. **EasySpider: 爬虫工具 v0.6.3**  
1. **Nessus: v2025.04.29(注册版)**  
- **username: admin**  
- **password: password**  
- **如需使用, 请先运行“开启服务”快捷方式。**  
- **Nessusd 服务开启后会自动编译插件, 期间 CPU 占用率较高, 编译完成后恢复正常, 具体进度可在Nessus Web 后台中查看。**  
1. **Invicti Netsparker: v25.5.0(注册版)**  
1. **MasScan: 端口扫描工具(Kali) v1.3.2**  
1. **Nmap: v7.97**  
1. **ObserverWard: 服务指纹识别工具 v2025.5.15**  
1. **RouterScan: C 段扫描工具 v2.60**  
1. **ScanBox:**  
- **文件夹下集成下列工具**  
- **AVScan: 杀毒软件检测工具**  
- **CheckAV**  
- **CDNScan: CDN 扫描工具**  
- **CDNCheck: v1.1.20**  
- **CF-Hero: v1.0.4**  
- **LeakScan: 敏感文件扫描工具**  
- **BBScan: v3.0**  
- **dirMap: v1.1**  
- **dirPro: v1.0**  
- **dirSearch: v0.4.3**  
- **DudeSuite: v1.2.0.3**  
- **DumpAll: v0.4.0**  
- **ForBy: .DS_Store 文件泄露利用工具 v1.0.1**  
- **Fuzz Faster U Fool v2.1.0**  
- **GitHack: v1.0**  
- **GitHacker: v1.1.3**  
- **Gobuster: v3.6.0**  
- **Golin: v1.2.6**  
- **Httpx v1.7.0**  
- **JoomScan: Kali**  
- **密探: v1.2.3**  
- **SnowShadow: v1.0**  
- **Spray: v1.2.1**  
- **svnExploit: v1.0**  
- **TscanPlus 无影: v2.8.2**  
- **URLFinder: v2023.9.9**  
- **WPScan: Kali**  
- **XSStrike v3.1.6**  
- **御剑**  
- **SubDomain 子域名探测工具**  
- **Amass v4.2.0**  
- **百川: v1.1**  
- **Censys v2.0**  
- **FlashSearch**  
- **FofaView: v1.1.15**  
- **GreyNoise**  
- **Hunter**  
- **InfoSearchAll: v1.2**  
- **Layer: 子域名挖掘机**  
- **ODIN**  
- **OneforAll: v0.4.5**  
- **Subfinder: v2.7.1**  
- **Sublist3r: v1.1**  
  
### [+] 权限工具 (C:\Penetration\ShellTools):  
  
1. **Antsword: 蚁剑(已集成插件) v4.0.3**  
1. **Behinder: 冰蝎**  
- **behinder 3.0 beta11**  
- **behinder 4.1**  
1. **ByPassBehinder: 冰蝎免杀 v1.0**  
1. **ByPassGodzilla: 哥斯拉免杀 v1.0**  
1. **Cobaltstrike:**  
- **猫猫二开: v4.5**  
- **坤坤二开: v4.5**  
- **集成插件 (C:\Penetration\ShellTools\CobaltStrike\Scripts)**  
- **ADCollection**  
- **AntiVirusCheck**  
- **BypassUserAdd**  
- **CrossC2 Kit**  
- **CS-AutoPostChain**  
- **EasyPersistent**  
- **Erebus: v1.3.6**  
- **EventLogMaster**  
- **LSTAR: v2022.01.15**  
- **mikasa**  
- **mr.xie: 谢公子插件**  
- **OLa**  
- **Pillager: v2024.09.07**  
- **taowu**  
1. **GBBypass: 冰蝎 & 哥斯拉 Webshell 免杀 v1.2**  
1. **Godzilla: 哥斯拉 v4.0.1**  
- **原版**  
- **ekp 二开版**  
1. **WSL Kali Linux 2025.1**  
- **username: kali password: kali**  
- **username: root password: root**  
- **修改软件源为阿里云**  
- **如需使用桌面环境, 请运行“开启 kex 服务”快捷方式, 输入 kali 密码后稍等 (不要关闭终端) 即可进入桌面环境, 进入桌面后按 F8 去除 Full screen 可使用窗口模式。**  
- **桌面环境非常占用系统资源, 建议非必要不开启, 使用完成后建议将 WSL Kali 关机释放内存。**  
- **kex 管理密码为 password, 日常使用时不会要求输入。**  
1. **Metasploit-Framework: (Kali)**  
1. **Msfvenom: MSF 木马生成工具(Kali)**  
1. **Skyscorpion: 天蝎 v1.0**  
1. **WebShell: 一句话木马(密码统一为 cmd)**  
- **Webshell 收集项目**  
1. **WebshellBypassedHuman: Webshell 免杀**  
1. **WebshellGenerate: Webshell 生成工具 v1.2.4**  
1. **XG拟态: Webshell 免杀工具 v2.5**  
  
### [+] 社工工具   
  
1. **Mip22: 钓鱼工具**  
1. **SocialEngineeringToolkit: 社工工具包(Kali)**  
1. **Swaks: 邮件伪造工具**  
  
### [+] 系统工具 (C:\Penetration\SystemTools):  
  
1. **7-Zip: v24.09(单文件版)**  
1. **Bandizip: 压缩工具(注册版) v7.37**  
1. **Clink 命令行增强工具 v1.7.19**  
1. **Dism++: 系统调节工具 v10.1.1002.1B**  
1. **Docker Desktop: v4.41.2(汉化版)**  
- **修改源为清华大学 & 网易 163**  
1. **Everything: 搜索工具 v1.4.1**  
1. **FastCopy: 复制工具 v5.9.0**  
1. **Git: v2.49.0**  
1. **HEU KMS Activator: 激活工具 v62.0**  
1. **IOBit:**  
- **AdvancedSystemcare: 优化清理工具(注册版) v18.0.3.240**  
- **DriverBooster: 驱动工具(注册版) v12.4.0.585**  
- **Uninstaller: 卸载工具(注册版) v14.3.1.8**  
- **SmartDefrag: 磁盘整理工具(注册版) v10.4.0.441**  
1. **Maye Lite: 快捷启动工具 v12.8.0.250416**  
1. **MenuManager: 右键菜单管理工具 v3.3.3.1**  
1. **NTLite: 系统调节工具 v2025.5**  
1. **OncePower: 批量重命名工具 v2.24.1**  
1. **Oh My Posh: 终端美化工具 v26.0.2**  
1. **OpenSSH SSH 协议工具 v10.0**  
1. **PCMaster: 系统调整工具**  
- **已创建右键快捷菜单:**  
- **在此处打开 Terminal 终端**  
- **在此处打开 Kali Linux 终端**  
- **在此处打开 Notepad**  
- **控制面板**  
- **计算器**  
- **注册表**  
1. **UltraISO: iso 编辑工具 v9.7.6**  
1. **wget & wget2**  
  
### [+] 主题工具 (C:\Penetration\ThemeTools):  
  
1. **ICON: 第三方图标**  
1. **Refresh: 存刷图标缓新工具**  
  
### [+] 流量工具 (C:\Penetration\TrafficTools):  
  
1. **BlueTeamTools: 流量解密工具 v2.1.8**  
1. **BurpSuite: v2025.2(注册版)**  
- **集成插件:**  
- **汉化**  
- **BurpFastJsonScan**  
- **BurpShiroPassiveScan**  
- **403Bypasser**  
- **burp-vulners-scanner**  
- **ChangeuUnicode**  
- **ChunkedCodingConverter**  
- **DomainHunterPro**  
- **FakeIP**  
- **FransLinkfinder**  
- **Hackbar**  
- **Log4j2Scan**  
- **Sqlmap4burp**  
- **TsojanScan**  
- **TurboIntruder**  
1. **Fiddler Debugger: 流量抓包工具(汉化版) v5.0**  
1. **Fiddler Everywhere: 流量抓包工具(注册版) v6.5.0**  
1. **Firefox: 集成插件版 v49.0**  
1. **Frp: 内网穿透工具 v0.62.1**  
1. **GoProxy v15.0**  
1. **GO Simple Tunnel: 隧道工具 v2.12.0**  
1. **Laragon: 集成环境 v8.1.0**  
1. **LiqunShield: Webshell 流量分析工具**  
1. **Netcat**  
- **Netcat: 原版 v1.11**  
- **Ncat: Nmap 重构版 v5.59**  
- **Rustcat: Rust 重构版 v3.0.0**  
1. **Neo-reGeorg: Http 隧道工具 v5.2.1**  
1. **NetSetMan: 网络参数设置工具 v5.4.0**  
1. **NETworkManager: 网络管理工具 v2025.1.18.0**  
1. **NPS: 内网代理工具 v0.26.10**  
1. **OpenVPN: VPN 工具 v3.7.2**  
1. **phpStudy: 集成环境 v8.1.1.3**  
1. **Proxifier: 流量代理工具(注册版) v4.1.4**  
1. **ProxyPin: 流量抓包工具 v1.1.9**  
1. **ShadowSocks: 科学上网工具 v4.4.1.0**  
1. **Stowaway: 内网穿透工具 v2.2**  
1. **Suo5: Http 隧道工具 v1.3.1**  
1. **TorBowser: 洋葱浏览器 v14.5.2**  
1. **v2rayN: 科学上网工具 v7.12.3**  
1. **WireShark: 流量抓包分析工具 v4.4.6**  
1. **Yakit: v1.4.1**  
  
## 全套虚拟机镜像:  
  
1. **Windows 7 x64**  
1. **Windows 8 x64**  
1. **Windows 10 x64**  
1. **Windows Server 2008 x64**  
1. **Windows Server 2012 x64**  
1. **Windows Server 2016 x64**  
1. **Windows Server 2019 x64**  
1. **Ubuntu 20 x64**  
- **所有虚拟机镜像均安装:**  
  
- **VMTools**  
- **7z**  
- **Microsoft Visual C++ 2008-2022 运行库**  
- **密钥或激活工具激活**  
- **可供测试软件, 环境搭建等用途。**  
  
- **虚拟机账号密码已备注在 VMware 描述栏处, 请注意查看。**  
  
  
  
  
0x03 更新说明  

```
由于微软即将对 Windows 10 结束技术支持, 故使用 Windows 11 母盘镜像制作;
所有运行库、系统组件、安装软件、脚本类工具均升级至最新版本, 并备注了对应的网站及版本号;
去除部分长期未更新、使用效果不佳的工具, 参考公众号推荐补充了部分新工具;
优化扫描器、数据库等部分工具自启动后台服务占用系统资源过大的问题;
重构工具的快捷方式，运行时显示详细使用参数及方法，并尽量为每一款工具配备相对好看的图标;
Maye 快速启动工具分类前添加英文字母索引, 方便快速定位分类，并添加了悬停简介;
Maye 界面单击工具图标运行, 个别工具启动速度可能较慢, 请耐心等待;
```

  
  
0x04 使用介绍  
  
📦  
开箱即用  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5hHSdBXqBIe35jdG0A1f9r3WI0anXpAnLLu8oJv8ZEJJfFfX7U4CO2JkDOwJ1FVbmj6pNhJW9AbA/640?wx_fmt=png&from=appmsg "")  
  
**Python 工具的说明:******  
  
**由于一些比较老的工具不兼容 python3.13 新版本的 pip 库, 且 Windows 共存不同版本的 python3 容易产生环境变量冲突问题, 所以在 WSL Kali 中同时安装了 python2、python3.8、python3.13 三个版本。****为降低不同工具间依赖库的冲突问题, 本镜像所有 python3 工具的 pip 依赖库均以虚拟环境形式安装 (python3 -m venv) 在项目根目录下 (Windows 为 “win” 文件夹, WSL Kali 为“kali” 文件夹)。使用前需要先激活对应的虚拟环境, 否则会报错缺少运行库。****本镜像所有 python 工具均配备了 start.bat 快速启动脚本, 会根据工具需求调用不同版本的 python 并自动激活对应的虚拟环境, 方便一键使用。如果您需要手动运行, 请确保先激活对应的虚拟环境。******  
  
**Oh-My-Posh 的说明:******  
  
**本镜像的 CMD Terminal、Powershell、WSL Kali Bash 三个终端均采用 Oh-My-Posh 美化;******  
  
**主题预览请参考 Oh-My-Posh 官网;******  
  
**更换 Oh-My-Posh 主题方法 (修改对应的主题名称即可), 具体请参考 Oh-My-Posh 官网:**  

```
CMD Terminal:
clink set ohmyposh.theme C:\Users\Anonymous\AppData\Local\Programs\oh-my-posh\themes\amro.omp.json
```


```
Powershell:
notepad C:\Users\Anonymous\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1
oh-my-posh init pwsh --config &#34;$env:POSH_THEMES_PATH\amro.omp.json&#34; | Invoke-Expression
```


```
WSL Kali Bash:
vim ~/.bashrc
eval &#34;$(/home/kali/.local/bin/oh-my-posh --init --shell bash --config ~/.poshthemes/amro.omp.json)&#34;
source ~/.bashrc
```

  
  
**0x05 内部VIP星球介绍-V1.4（福利）**  
  
        如果你想学习更多**渗透测试技术/应急溯源/免杀/挖洞赚取漏洞赏金/红队打点**  
欢迎加入我们**内部星球**  
可获得内部工具字典和享受内部资源和  
内部交流群，**每1-2天更新1day/0day漏洞刷分上分****(2025POC更新至4000+)**  
**，**  
包含网上一些**付费****工具及BurpSuite自动化漏****洞探测插件，AI代审工具等等**  
。shadon\Quake\  
Fofa高级会员，CTFshow等各种账号会员共享。详情直接点击下方链接进入了解，觉得价格高的师傅可后台回复"   
**星球**  
 "有优惠券名额有限先到先得！全网资源  
最新  
最丰富！**（🤙截止目前已有1900多位师傅选择加入❗️早加入早享受）**  
  
****  
**内部星球25HVV漏洞库：**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5hHSdBXqBIe35jdG0A1f9rRBJh5ibwOEEDRFuCeibr2sy63yiblsjjGW96lpQZdHa1N0Ao5icZ8IiajDg/640?wx_fmt=png&from=appmsg "")  
  
  
**👉****点击了解加入-->>内部VIP知识星球福利介绍V1.4版本-1day/0day漏洞库及内部资源更新**  
  
  
结尾  
  
# 免责声明  
  
  
# 获取方法  
  
  
**公众号回复20250701获取下载**  
  
# 最后必看-免责声明  
  
  
      
文章中的案例或工具仅面向合法授权的企业安全建设行为，如您需要测试内容的可用性，请自行搭建靶机环境，勿用于非法行为。如  
用于其他用途，由使用者承担全部法律及连带责任，与作者和本公众号无关。  
本项目所有收录的poc均为漏洞的理论判断，不存在漏洞利用过程，不会对目标发起真实攻击和漏洞利用。文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用。  
如您在使用本工具或阅读文章的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。本工具或文章或来源于网络，若有侵权请联系作者删除，请在24小时内删除，请勿用于商业行为，自行查验是否具有后门，切勿相信软件内的广告！  
  
  
  
# 往期推荐  
  
  
**1.内部VIP知识星球福利介绍V1.4（AI自动化工具）**  
  
**2.CS4.8-CobaltStrike4.8汉化+插件版**  
  
**3.最新BurpSuite2025.2.1专业版（新增AI模块）**  
  
**4. 最新xray1.9.11高级版下载Windows/Linux**  
  
**5. 最新HCL AppScan Standard**  
  
  
渗透安全HackTwo  
  
微信号：关注公众号获取  
  
后台回复星球加入：  
知识星球  
  
扫码关注 了解更多  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6qFFAxdkV2tgPPqL76yNTw38UJ9vr5QJQE48ff1I4Gichw7adAcHQx8ePBPmwvouAhs4ArJFVdKkw/640?wx_fmt=png "二维码")  
  
  
  
[全面资产收集流程及方法解析 万字长文窥探信息收集|挖洞技巧](https://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247491574&idx=1&sn=48d865c82a228bd135a035419c765e94&scene=21#wechat_redirect)  
  
  
