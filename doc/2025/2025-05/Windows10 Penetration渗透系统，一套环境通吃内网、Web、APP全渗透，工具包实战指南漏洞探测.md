#  Windows10 Penetration渗透系统，一套环境通吃内网、Web、APP全渗透，工具包实战指南|漏洞探测   
makoto56  渗透安全HackTwo   2025-05-28 16:00  
  
0x01 工具介绍  
  
  
渗透测试套件工具集是一款基于Windows 10打造的一体化安全测试环境，集成了400多种专业工具，涵盖Web渗透、移动安全、内网攻防、社会工程学等多个领域。内置WSL2 Kali Linux，搭配Burp Suite、Metasploit、Cobalt Strike等核心工具，并预装多种数据库环境和编程语言支持。该套件针对性能优化，界面美观，使安全专业人员无需繁琐配置即可快速开展工作，是渗透测试人员的得力助  
。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7jtjhzRWsjKNZRZpnQicfPM1AiaXXdyvdC4A1Zvt1ZU2R7ibZt3GfQJO7sL0WBQIArzhhbOcI143R7g/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
基于 Windows10 Workstation 22H2 x64 原版镜像制作(不适用于ARM设备)；1. **完整安装 WSL2 Kali Linux 2024.1；**  
- **注: 物理主机必须支持 CPU 虚拟化功能，否则 WSL2 无法使用！**  
- **开启 VMware - 虚拟机设置 - 处理器 - 虚拟化引擎:**  
- **虚拟化 Intel VT-x/EPT 或 AMD-V/RVI**  
- **虚拟化 CPU 性能计数器**  
- **虚拟化 IOMMU(IO 内存管理单元)**  
1. **精简系统自带软件，美化字体及部分图标，适度优化；**  
- **推荐运行环境:**  
- **VMware: 16.x(建议视情分配图形内存)**  
- **运行内存: 8G**  
- **固态硬盘: 300G**  
# 免责声明:  
# 本镜像仅面向合法授权的企业安全建设行为，如您需要测试本镜像的可用性，请自行搭建靶机环境；在使用本镜像进行检测时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权；如您在使用本镜像的过程中存在任何非法行为，您需自行承担相应后果，作者将不承担任何法律及连带责任；本镜像所使用的工具资源均来自于网友投稿及互联网整理，作者仅提供分享交流平台，不为其版权负责。如果您发现本镜像中有侵犯您(或贵司)知识产权的资源，请及时反馈，作者会第一时间进行修改或删除。  
# 软件及工具介绍:  
# Windows App:  
1. **Windows Terminal**  
1. **TranslucentTB**  
## 渗透测试:  
### [+] 人工智能 (C:\Penetration\AiTools) :  
1. **ChatGPT**  
1. **HackerGPT**  
### [+] 安卓工具 (C:\Penetration\AndroidTools):  
1. **AndroidHelper: APK 逆向工具**  
1. **AndroidKiller: APK 综合工具**  
1. **Apk2url: APK 信息提取工具**  
1. **APKDeepLens: APK 扫描工具**  
1. **Apkinfo: APK 分析工具**  
1. **Apkleaks: APK 扫描工具**  
1. **ApkScan-PKID: APK 查壳工具**  
1. **Apktool: APK 反编译工具**  
1. **ApkToolPlus: APK 反编译分析工具**  
1. **AppMessenger: APK 分析工具**  
1. **BlueStacks: 蓝叠安卓模拟器(安卓9.0)**  
- **已安装:**  
- **Debug Proxy**  
- **Dev Tools**  
- **Http Canary**  
- **JuiceSSH**  
- **MT Manager**  
- **Net Capture**  
- **Packet Capture**  
- **Terminal Emulator**  
1. **BytecodeViewer: 字节码查看工具**  
1. **Dextools: Dex 打包工具**  
1. **Jadx: 反编译工具**  
1. **JavaDecompiler: 字节码查看工具**  
1. **SuperJadx: 反编译工具**  
1. **Yaazhini: APK 漏洞扫描工具**  
### [+] 免杀工具 (C:\Penetration\AntivirusTools):  
1. **AvEvasionCraftOnline**  
1. **Aycvxz**  
1. **Charlotte**  
1. **Invoke-Obfuscation**  
1. **LoaderFly**  
1. **Powershell-Obfuscation**  
1. **Sandboxie: 沙盒工具**  
1. **VMProtect: 3.8.4(注册版)**  
1. **VProtect: 加壳工具**  
### ....  
1. **FDM: 下载工具**  
1. **Telegram**  
### [+] 办公工具 (C:\Penetration\OfficeTools):  
  
     Office: Word + Excel + Powerpoint + Access + Onenote + Outlook1. **WPS: 11.8.2.12195 专业增强版**  
### [+] 编程工具 (C:\Penetration\ProgramTools):  
  
      Go1. **Java:**  
- **jre1.8.0: 已配置环境变量，系统默认调用 Java8**  
- **jre15.0.2: 绿色版，如有软件需要java15环境运行可直接调用/bin/java.exe即可**  
- **jdk21: 绿色版，如有软件需要java21环境运行可直接调用/bin/java.exe即可**  
1. **JetBrains: 2024.1(注册版)**  
- **CLion**  
- **DataGrip**  
- **GoLand**  
- **IntelliJ**  
- **PhpStorm**  
- **PyCharm**  
- **Rider**  
- **WebStorm**  
- **如遇到激活状态失效，请手动运行/JetBrains/破解补丁/目录下的破解脚本。**  
1. **MinGW64**  
1. **Nim**  
1. **Nodejs**  
1. **Python:**  
- **python2: python2命令启动(python2 test.py)**  
- **python3: python3命令启动(python3 test.py)**  
- **已集成本镜像所有工具的 pip 依赖库****(如有遗漏未安装的库请自行安装)**  
- **使用 pip 命令调用 python3 pip**  
1. **TDM-GCC**  
1. **VisualStudio 2022: 社区版**  
### [+] 逆向工具 (C:\Penetration\ReverseTools):  
  
bat2exe: BAT 转 EXE 工具1. **DetectItEasy: 查壳工具**  
1. **dnSpy: .Net 逆向工具**  
1. **exeScope: EXE 编辑工具**  
1. **Ghidra: 逆向工具**  
1. **GhostExplore: GHO 文件编辑工具**  
1. **GreenHelper: EXE 绿化工具**  
1. **HashTool: Hash 计算工具**  
1. **Html2exe: Html 打包工具**  
1. **IDAPro**  
1. **ILSpy: .Net 逆向工具**  
1. **OllyDebug: 1.10 吾爱破解修复增强版**  
1. **PeiD: 查壳工具**  
1. **SignTool: 签名伪造工具**  
1. **UPX: 加壳工具**  
1. **vbs2exe: VBS 转 EXE 工具**  
1. **x64Debug: EXE 调试工具**  
### [+] 扫描工具 (C:\Penetration\ScanTools):  
  
Acunetix: 24.2.240226074(注册版)- **username: admin@awvs.com**  
- **password: Admin@awvs.com**  
- **如需使用请先运行开启服务快捷方式**  
1. **AppScan: 10.4.0(注册版)**  
1. **EasySpider: 爬虫工具**  
1. **Nessus: 10.7.1(注册版)**  
- **username: admin**  
- **password: password**  
- **如需使用请先运行开启服务快捷方式**  
- **Nessusd 服务开启后会自动编译插件，CPU 占用率较高，编译完成后恢复正常，具体进度可在Nessus Web 后台中查看。**  
1. **Invicti Netsparker: 24.3(注册版)**  
1. **Nmap**  
1. **RouterScan: C段扫描工具**  
1. **ScanBox**  
> **AVScan 杀毒软件检测工具:**  
  
- **CheckAntivirus(自己写的，如有需要可随便使用)**  
> **CDNScan CDN 扫描工具:**  
  
- **CDNCheck-go**  
- **CDNCheck-python**  
> **LeakScan 敏感文件扫描工具:**  
  
- **BBScan**  
- **Caesar**  
- **dirMap**  
- **dirPro**  
- **dirSearch**  
- **DudeSuite**  
- **DumpAll**  
- **GitHack**  
- **GitHacker**  
- **Gobuster**  
- **Golin**  
- **ihoneyBakFileScan**  
- **JoomScan: Kali**  
- **JSFinder**  
- **密探**  
- **PackerFuzzer**  
- **SSRFmap**  
- **svnExploit**  
- **TscanPlus**  
- **URLFinder**  
- **wFuzz**  
- **WPScan: Kali**  
- **御剑**  
> **SubDomain 子域名探测工具:**  
  
- **百川**  
- **FofaView: Fofa 查询工具**  
- **InfoSearchAll**  
- **Layer: 子域名挖掘机**  
- **OneforAll**  
- **Securitytrails: Securitytrails 官方 API 脚本**  
- **SnowShadow**  
- **Subfinder**  
- **Sublist3r**  
- **WebBatchRequest**  
### [+] 权限工具 (C:\Penetration\ShellTools):  
  
Antsword: 蚁剑(已集成插件)1. **Behinder: 冰蝎**  
- **behinder 3.0 beta11**  
- **behinder 4.1**  
1. **ByPassBehinder: JSP 免杀工具**  
1. **Cobaltstrike: 猫猫二开**  
- **使用CSAgent汉化**  
- **集成插件 (C:\Penetration\ShellTools\CobaltStrike\Scripts)**  
- **ADCollection**  
- **bypassav**  
- **BypassUserAdd**  
- **CobaltStrike_CNA**  
- **CobaltStrikeShellcodeGenerator**  
- **erebus**  
- **eventlogmaster**  
- **LSTAR**  
- **mikasa**  
- **mr.xie: 谢公子插件**  
- **OLA**  
- **Pillager**  
- **taowu**  
1. **DNSCat2**  
1. **GBBypass: 冰蝎 & 哥斯拉 Webshell 免杀**  
1. **Godzilla: 哥斯拉**  
1. **Kali:WSL Kali Linux 2024.1**  
- **username: kali password: kali**  
- **username: root password: root**  
- **修改软件源为阿里云**  
- **图形化模式非常占用系统资源，建议非必要不开启。**  
1. **Metasploit-Framework: Kali**  
1. **Msfvenom: MSF 木马生成工具**  
1. **Skyscorpion: 天蝎**  
1. **WebShell: 一句话木马(密码统一为cmd)**  
- **Webshell: Webshell 收集项目**  
1. **WebshellBypassedHuman: Webshell 免杀**  
1. **WebshellGenerate: Webshell 生成工具**  
1. **XG拟态: Webshell 免杀工具**  
### [+] 社工工具 (C:\Penetration\SocialEngineeringTools):  
  
Mip22: 钓鱼工具1. **SocialEngineeringToolkit: 社工工具包(Kali)**  
1. **SocialFish: 钓鱼工具**  
1. **Swaks: 邮件伪造工具**  
### [+] 系统工具 (C:\Penetration\SystemTools):  
  
7-Zip: 23.0 单文件版1. **AAct: 激活工具**  
1. **Bandizip: 压缩工具(注册版)**  
1. **curl**  
1. **Dism++: 系统调节工具**  
1. **Everything: 搜索工具**  
1. **Git**  
1. **HackBGRT: Windows 开机 Logo 更换工具**  
1. **IOBit:**  
- **AdvancedSystemcare: 优化清理工具(注册版)**  
- **DriverBooster: 驱动工具(注册版)**  
- **SmartDefrag: 磁盘整理工具(注册版)**  
- **Uninstaller: 卸载工具(注册版)**  
1. **Keyboard2Mouse: 键盘操作鼠标**  
1. **Maye: 快捷启动工具**  
1. **MenuManager: 右键菜单管理工具**  
1. **NTLite: 系统调节工具**  
1. **PCMaster: 系统调整工具**  
- **已创建右键快捷菜单:**  
- **在此处打开 Terminal 终端**  
- **在此处打开 Kali Linux 终端**  
- **在此处打开 Git 终端**  
- **在此处打开Notepad**  
- **控制面板**  
- **计算器**  
- **注册表**  
1. **UltraISO: iso编辑工具**  
1. **wget**  
### [+] 主题工具 (C:\Penetration\ThemeTools):  
  
ICON: 图标1. **ICONSext: 图标提取工具**  
1. **MacType: 更换字体工具**  
1. **OldNewExplorer: 资源管理器调整工具**  
1. **Refresh: 图标缓存刷新工具**  
### [+] 流量工具 (C:\Penetration\TrafficTools):  
  
BlueTeamTools: 流量解密工具1. **BurpSuite: 2024.2.1(注册版)**  
- **集成插件:**  
- **汉化**  
- **BurpFastJsonScan**  
- **BurpJSLinkFinder**  
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
1. **FiddlerDebugger: 流量抓包工具(汉化版)**  
1. **FiddlerEverywhere: 流量抓包工具(注册版)**  
1. **Firefox:firefox 49.0 集成插件版**  
1. **ftpServers: FTP 开启工具**  
1. **LiqunShield: Webshell流量分析工具**  
1. **Netcat: NC**  
1. **NetSetMan: 网络参数设置工具**  
1. **OpenVPN: VPN 工具**  
1. **phpStudy: 集成环境**  
1. **Proxifier: 流量代理工具(注册版)**  
1. **ShadowSocks: 科学上网工具**  
1. **TorBowser: 洋葱浏览器**  
1. **v2rayN: 科学上网工具**  
1. **WireShark: 流量抓包分析工具**  
1. **Yakit**  
# 全套虚拟机镜像:  
  
Windows 7 x641. **Windows 8 x64**  
1. **Windows 10 x64**  
1. **Windows Server 2008 x64**  
1. **Windows Server 2012 x64**  
1. **Windows Server 2016 x64**  
1. **Windows Server 2019 x64**  
1. **Ubuntu 20 x64**  
# 所有虚拟机镜像均安装：  
- **VMTools**  
- **7z**  
- **Microsoft Visual C++ 2008-2022 运行库**  
- **密钥或激活工具激活**  
**可供测试软件，环境搭建等用途。**  
 **虚拟机账号密码已备注在 VMware 描述栏处，请注意查看。**  
# 参考截图:  
#          
  
  
  
0x03 更新说明  
  
```
由于部分用户反馈 ova 文件导入失败，现重新上传压缩包版本，解压后打开 vmx 文件即用。
```  
  
  
0x04 使用介绍  
  
📦  
开箱即用  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7jtjhzRWsjKNZRZpnQicfPMwXhoYLslniaa2IwUbkjZibS3JJgUMkpoCvuAwv9Q0UGosGicSl9WqB2dg/640?wx_fmt=png&from=appmsg "")  
  
  
**0x05 内部VIP星球介绍-V1.4（福利）**  
  
        如果你想学习更多**渗透测试技术/应急溯源/免杀/挖洞赚取漏洞赏金/红队打点**  
欢迎加入我们**内部星球**  
可获得内部工具字典和享受内部资源和  
内部交流群，**每1-2天更新1day/0day漏洞刷分上分****(2025POC更新至3900+)**  
**，**  
包含网上一些**付费****工具及BurpSuite自动化漏****洞探测插件，AI代审工具等等**  
。shadon\Quake\  
Fofa高级会员，CTFshow等各种账号会员共享。详情直接点击下方链接进入了解，觉得价格高的师傅可后台回复"   
**星球**  
 "有优惠券名额有限先到先得！全网资源  
最新  
最丰富！**（🤙截止目前已有1800多位师傅选择加入❗️早加入早享受）**  
  
****  
  
**👉****点击了解加入-->>内部VIP知识星球福利介绍V1.4版本-1day/0day漏洞库及内部资源更新**  
  
****  
  
  
结尾  
  
# 免责声明  
  
  
# 获取方法  
  
  
**公众号回复20250529获取下载**  
  
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
  
  
