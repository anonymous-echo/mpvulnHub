#  研究人员发现华硕预装软件DriverHub存在"一键式"远程代码执行漏洞   
鹏鹏同学  黑猫安全   2025-05-13 01:19  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEce9BQ6ka98O4HfvB8lHhIAibKdZWxDdrvbstCaXYlME6iaQcsPJVzW6hBwXu5UYYoMaSIvicb3aJTm3aQ/640?wx_fmt=png&from=appmsg "")  
  
安全研究人员"MrBruh"在华硕主板预装的驱动程序DriverHub中发现两个漏洞（编号CVE-2025-3462，CVSS评分8.4；CVE-2025-3463，CVSS评分9.4）。远程攻击者可利用这些漏洞实现任意代码执行。  
  
这两个漏洞均源于验证机制不足，导致攻击者可滥用DriverHub功能。华硕公司指出相关漏洞不影响笔记本电脑和台式机。  
  
DriverHub是一款无图形界面的驱动更新程序，其后台进程通过本地53000端口的RPC与driverhub.asus.com通信。研究发现，虽然该程序仅接受源标头为"driverhub.asus.com"的请求，但由于通配符匹配缺陷，类似"driverhub.asus.com.mrbruh.com"的域名也可通过验证，这使得攻击者可借此漏洞安装恶意软件。  
  
研究人员发现DriverHub暴露了多个本地RPC端点，其中包括高危的UpdateApp功能——该功能会下载并安装经华硕签名的可执行文件（需管理员权限）。通过分析JavaScript和反编译代码，MrBruh发现驱动安装使用的压缩包中包含INI配置项（SilentInstallRun），可在静默安装期间执行任意命令，从而开辟远程代码执行（RCE）路径。  
  
"关键文件包括AsusSetup.exe、AsusSetup.ini和SilentInstall.cmd。当执行AsusSetup.exe时，程序首先读取包含驱动元数据的AsusSetup.ini文件。其中SilentInstallRun参数引起了我的注意。"报告指出，"双击运行AsusSetup.exe会启动图形安装界面，但若使用-s参数（DriverHub静默安装的调用方式），程序将执行SilentInstallRun指定的任何命令。虽然当前配置仅运行自动安装驱动的cmd脚本，但实际上可执行任意操作。"  
  
完整的攻击链会滥用DriverHub更新机制：伪造子域名的恶意网站首先诱导下载看似正常的可执行文件与精心构造的AsusSetup.ini，随后下载合法的华硕签名文件AsusSetup.exe。该程序将以管理员权限静默运行，并执行.ini文件中指定的攻击者载荷（如calc.exe）。  
  
MrBruh于4月7日发现漏洞并于次日提交报告，华硕在5月9日发布了安全更新。当研究人员询问漏洞赏金计划时，华硕表示暂不提供现金奖励，但会将研究者列入"荣誉名单"。  
  
  
  
