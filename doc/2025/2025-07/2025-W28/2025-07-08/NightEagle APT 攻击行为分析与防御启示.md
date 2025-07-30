> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkzMzMyOTc5OQ==&mid=2247484107&idx=1&sn=308f4d5e3615675f93acbe3fbe61e57a

#  NightEagle APT 攻击行为分析与防御启示  
梦幻的彼岸  梦幻的彼岸   2025-07-08 07:07  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/OygvOwS4DnvofKvt5Y1QcE5BLwVY0uygJkFHaxaADciaE89BT22GQg8G5m3IRsnBv5t3DgSs187nOkI0xPjehag/640?wx_fmt=jpeg&from=appmsg "")  
# 一、事件由来  
  
    在2025年马来西亚国家网络防御与安全展览暨会议上，奇安信披露了一个名为 NightEagle 的 APT 组织正对我国家发起具有高度隐蔽性的高级持续性威胁（俗称APT）攻击。  
  
    该组织长期瞄准我国高科技、芯片半导体、量子技术、人工智能与大模型、军工等重点行业中的核心企业和科研单位，开展定向网络攻击，其主要目的在于窃取关键技术情报。攻击完成后，攻击者通常会迅速撤离目标系统，并抹除所有入侵痕迹，展现出极强的隐蔽性和战术素养。  
## （一）相关脉络梳理  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OygvOwS4DnvofKvt5Y1QcE5BLwVY0uygmS9ZHKTnzFsAgjI72AFUpPt5jUfXbZE1bPibwZMA7UsEQyrqPEJ81jQ/640?wx_fmt=png&from=appmsg "")  
  
# 二、自查方法  
## （一）攻击特征  
### 1、Exchange 邮件服务器  
#### （1）是否存在可疑文件  
  
判断 Windows .NET 安装路径 C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files\ews\下是否存在指定格式的文件名，总结成正则表达式判断，是否存在为 cal、zh、cn 的文件名或其他语言版本缩写，且存在后面有三位数字的文件名。  
  
例如：  

```
App_Web_cal728.aspx.cdb7cbf8.n5q9vicf.dll
App_Web_cn.aspx.d452ffe4.a0ouixey.dll
App_Web_cn274.aspx.b760cbf5.rcirk_ic.dll
App_Web_cn304.aspx.1221cc01.liudbjfz.dll
App_Web_zh.aspx.b137e928.n546mfkn.dll
App_Web_zh371.aspx.4ed1141f.iecxfmum.dll
App_Web_zh401.aspx.b760cbf5.ek9d9hh4.dll
```

#### （2）可疑日志  
  
对位于 C:\inetpub\logs\LogFiles\W3SVC1\ 路径下的邮件服务器 IIS 日志文件进行检查，判断其中是否存在以下两个特定 User-Agent 的访问记录  
  
1、邮件收取阶段使用的 User-Agent ：  

```
Microsoft+Office/16.0+(Microsoft+Outlook+Mail+16.0.6416;+Pro)
```

  
2、服务器渗透阶段使用的 User-Agent ：   

```
Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/105.0.0.0+Safari/537.36
```


```


```

  
并检查路径 C:\inetpub\logs\LogFiles\W3SVC1\ 下的 IIS 日志文件，判断是否存在包含 POST /owa/auth/logoff.aspx 请求的记录  
#### （3）排查脚本示例  
  
PowerShell 排查脚本代码示例：  
  
备注：只是示例参考作用，需根据实际情况修改   

```
# 设置颜色便于输出识别
function Write-Section([string]$text) {
    Write-Host &#34;==================== $text ====================&#34; -ForegroundColor Cyan
}


function Write-Found([string]$text) {
    Write-Host &#34;[FOUND] $text&#34; -ForegroundColor Red
}


function Write-Info([string]$text) {
    Write-Host &#34;[INFO] $text&#34; -ForegroundColor Green
}


# 1. 检查 ASP.NET 缓存目录中的可疑文件
Write-Section &#34;检查 ASP.NET 缓存文件&#34;


$aspNetPath = &#34;C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files\ews&#34;
$regexPattern = '^App_Web_(cal|zh|cn)(\d{3})?\.aspx\.[a-f0-9]+\.(?:[a-zA-Z0-9_\-]+)\.dll$'


if (Test-Path $aspNetPath) {
    $foundFiles = Get-ChildItem -Path $aspNetPath -Recurse -File | Where-Object {
        $_.Name -match $regexPattern
    }


    if ($foundFiles) {
        foreach ($file in $foundFiles) {
            Write-Found &#34;发现可疑 ASP.NET 文件: $($file.FullName)&#34;
        }
    } else {
        Write-Info &#34;未发现可疑 ASP.NET 缓存文件。&#34;
    }
} else {
    Write-Info &#34;ASP.NET 缓存路径不存在：$aspNetPath&#34;
}


# 2. 检查邮服日志中的可疑行为
Write-Section &#34;检查邮服日志文件&#34;


$logPath = &#34;C:\inetpub\logs\LogFiles\W3SVC1\*.log&#34;


# 2.1 检查是否包含 POST /owa/auth/logoff.aspx
Write-Info &#34;正在查找 POST /owa/auth/logoff.aspx 请求...&#34;
$postRequests = Select-String -Path $logPath -Pattern &#34;POST /owa/auth/logoff\.aspx&#34; -SimpleMatch


if ($postRequests) {
    foreach ($req in $postRequests) {
        Write-Found &#34;发现可疑 POST 请求: $($req.Line)&#34;
    }
} else {
    Write-Info &#34;未发现 POST /owa/auth/logoff.aspx 请求。&#34;
}


# 2.2 检查 Outlook 客户端 User-Agent
Write-Info &#34;正在查找 Outlook Mail User-Agent...&#34;
$uaOutlook = Select-String -Path $logPath -Pattern &#34;Microsoft\+Office\/16\.0\s*$Microsoft\+Outlook\+Mail\+16\.0\.6416;\+Pro$&#34; -CaseSensitive


if ($uaOutlook) {
    foreach ($req in $uaOutlook) {
        Write-Found &#34;发现 Outlook Mail User-Agent: $($req.Line)&#34;
    }
} else {
    Write-Info &#34;未发现 Outlook Mail User-Agent。&#34;
}


# 2.3 检查 Chrome 渗透 User-Agent
Write-Info &#34;正在查找 Chrome 渗透 User-Agent...&#34;
$uaChrome = Select-String -Path $logPath -Pattern &#34;Mozilla\/5\.0\s*$Windows NT 10\.0; Win64; x64$\s*AppleWebKit\/537\.36\s*$KHTML, like Gecko$\s*Chrome\/105\.0\.0\.0 Safari\/537\.36&#34; -CaseSensitive


if ($uaChrome) {
    foreach ($req in $uaChrome) {
        Write-Found &#34;发现 Chrome 渗透 User-Agent: $($req.Line)&#34;
    }
} else {
    Write-Info &#34;未发现 Chrome 渗透 User-Agent。&#34;
}


Write-Section &#34;排查完成&#34;
```

  
  
使用方法：  
  
打开 PowerShell（以管理员身份运行）  
  
将上述脚本保存为 .ps1 文件，例如：Check-APT-NightEagle.ps1  
  
在 PowerShell 中执行：   

```
.\Check-APT-NightEagle.ps1
```


```


```

  
⚠️ 注意：首次运行 .ps1 文件时，可能需要设置执行策略：    

```
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```


```


```

  
#### （4）360发布的Exchange内存自检工具  
  
发布地址：https://bbs.360.cn/thread-16164186-1-1.html  
  
工具下载链接：  
http://down.360safe.com/EmergencyDetect64.exe  
  
使用图片：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OygvOwS4DnvofKvt5Y1QcE5BLwVY0uygicYFdE7tiaIExrnYBGTWHBdbEfSuJH9QCCYAB9qERDPUQ0qloqTVGsPQ/640?wx_fmt=png&from=appmsg "")  
  
# 三、加固探讨  
  
    在面对像 NightEagle APT（APT-Q-95） 这类使用 0day 漏洞链攻击 的高级持续性威胁时，传统的基于特征码的检测方式往往失效。因此，必须从多维度、多层次构建纵深防御体系 ，并结合行为分析、日志审计、内存检测等手段进行主动发现。  
## （一）防御与发现思路总结  
<table><tbody><tr><td valign="middle" align="left"><section><span leaf="">防御阶段</span></section></td><td valign="middle" align="left"><section><span leaf="">关键策略</span></section></td></tr><tr><td valign="middle" align="left"><span style=""><span leaf="">事前预防</span></span></td><td valign="middle" align="left"><span style=""><span leaf="">强化系统基线、漏洞修复、最小权限原则、邮件安全网关</span></span></td></tr><tr><td valign="middle" align="left"><span style=""><span leaf="">事中发现</span></span></td><td valign="middle" align="left"><span style=""><span leaf="">日志监控、行为异常检测、内存驻留检测、网络流量分析</span></span></td></tr><tr><td valign="middle" align="left"><span style=""><span leaf="">事后响应</span></span></td><td valign="middle" align="left"><span style=""><span leaf="">IOC 提取、溯源反制、隔离清除、报告复盘</span></span></td></tr></tbody></table>  
  
## （二）具体防御与发现措施  
### 1、强化基础防护机制  
#### （1）系统加固  

```
定期更新 Exchange Server、Windows 补丁；
关闭非必要服务和端口（如未使用的 IIS 组件）；
启用强身份认证（如 MFA）、限制特权账户使用；
对服务器启用 AppLocker 或 WDAC，防止未知 DLL 加载。
```

#### （2）邮件系统防护  

```
部署邮件网关或沙箱设备，对附件、链接进行静态分析与动态执行；
使用 SPF/DKIM/DMARC 技术防止伪造发件人；
监控 /owa/auth/ 路径下的异常访问请求。
```

  
### 2、基于行为的威胁感知  
### （1）日志行为分析  

```
IIS 日志 ：检查是否有异常 User-Agent 请求；
Exchange 访问日志 ：识别非常规时间登录、批量导出邮箱数据的行为；
PowerShell 日志 ：关注可疑命令执行（如 Add-Type, Invoke-Expression）；
Windows 安全日志 ：监控账户提权、远程登录、计划任务创建等高危操作。
```

  
#### （2）内存行为检测  
  
    面对日益复杂的 0day 攻击手段，仅依赖传统的边界防御和签名识别已难以有效应对。建议企业及个人用户在加强系统基线防护的同时，积极引入基于内存保护机制的安全策略，以提升对未知威胁的检测与拦截能力。  
  
当前可采用的一类重要技术是内存安全防护体系 ，其核心思想在于通过对运行时内存行为进行实时监控与干预，阻止攻击者利用漏洞注入恶意代码或执行无文件攻击等高级威胁方式。  
  
该类技术主要包含两个层面的防护组件：  
  
一、主机端内存保护机制  
  
部署于服务器或关键业务主机之上，能够有效防御诸如：  

```
利用内存漏洞进行的攻击；
内存马（Memory Webshell）驻留；
无需落盘即可执行的恶意行为；
```

  
通过深度内核级防护，实现对主机运行时环境的主动防御，弥补传统杀毒软件和防火墙的不足。  
  
二、终端内存保护机制  
  
面向 PC 终端设备设计，具备如下能力：  

```
实时监测并阻断内存中异常代码执行；
防御无文件攻击、反射式 DLL 注入、进程注入等新型攻击手法；
在不依赖特征库的前提下，提升对未知威胁的识别与响应效率。
```

  
结合上述两种防护机制，可构建覆盖“主机 + 终端”的一体化内存安全防护体系，显著增强对 APT 攻击、0day 漏洞利用链等复杂威胁的抵御能力。  
### 3、网络流量监测与威胁狩猎  
#### （1）NDR（网络检测与响应）  

```
部署 NDR 平台，对加密流量进行深度解析；
检测 C2 通信行为（如连接恶意域名 app.flowgw.com）；
分析 DNS 请求、长连接、低频高带宽传输等异常流量模式。
```

  
#### （2）流量回溯与取证  
  
保存原始 PCAP 数据，便于后续分析攻击路径；  
  
结合 SIEM 平台关联主机日志、网络行为、用户行为进行综合研判。  
#### 4、利用威胁情报提升检测效率  
#### （1）IOC 匹配与阻断  
  
将已知恶意域名、IP 地址加入黑名单（如 synologyupdates.com、e-mailrelay.com）；  
  
在防火墙、WAF、DNS 层面设置规则拦截；  
  
使用 YARA 规则匹配可疑文件或内存代码段。  
  
相关IOC示例：  
  
  
   

```
&#34;apt nighteagle&#34;,&#34;liveupdate.wsupdatecloud.net&#34;
&#34;apt nighteagle&#34;,&#34;comfyupdate.org&#34;
&#34;apt nighteagle&#34;,&#34;saperpcloud.com&#34;
&#34;apt nighteagle&#34;,&#34;rhel.lvusdupdates.org&#34;
&#34;apt nighteagle&#34;,&#34;flowgw.com&#34;
&#34;apt nighteagle&#34;,&#34;daihou360.com&#34;
&#34;apt nighteagle&#34;,&#34;app.flowgw.com&#34;
&#34;apt nighteagle&#34;,&#34;update.saperpcloud.com&#34;
&#34;apt nighteagle&#34;,&#34;update.haprxy.org&#34;
&#34;apt nighteagle&#34;,&#34;threatbookav.com&#34;
&#34;apt nighteagle&#34;,&#34;tracking.doubleclicked.com&#34;
&#34;apt nighteagle&#34;,&#34;wsupdatecloud.net&#34;
&#34;apt nighteagle&#34;,&#34;sangsoft.net&#34;
&#34;apt nighteagle&#34;,&#34;ms.wsupdatecloud.net&#34;
&#34;apt nighteagle&#34;,&#34;haprxy.org&#34;
&#34;apt nighteagle&#34;,&#34;coremailtech.com&#34;
&#34;apt nighteagle&#34;,&#34;ccproxy.org&#34;
&#34;apt nighteagle&#34;,&#34;ms-nipre.com&#34;
&#34;apt nighteagle&#34;,&#34;shangjuyike.com&#34;
&#34;apt nighteagle&#34;,&#34;lvusdupdates.org&#34;
&#34;apt nighteagle&#34;,&#34;doubleclicked.com&#34;
&#34;apt nighteagle&#34;,&#34;mirrors-openjdk.org&#34;
&#34;apt nighteagle&#34;,&#34;wechatutilities.com&#34;
&#34;apt nighteagle&#34;,&#34;synologyupdates.com&#34;
&#34;apt nighteagle&#34;,&#34;fortisys.net&#34;
&#34;apt nighteagle&#34;,&#34;cloud.synologyupdates.com&#34;
&#34;apt nighteagle&#34;,&#34;fastapi-cdn.com&#34;
&#34;apt nighteagle&#34;,&#34;e-mailrelay.com&#34;
&#34;apt nighteagle&#34;,&#34;updates.ccproxy.org&#34;
&#34;apt nighteagle&#34;,&#34;mirror1.mirrors-openjdk.org&#34;
&#34;apt nighteagle&#34;,&#34;dashboard.daihou360.com&#34;
```


```


```

  
5、情报订阅与共享  
  
接入主流威胁情报平台；  
  
关注 APT 组织活动趋势（如 NightEagle 攻击时间集中在北京时间晚 9 点至凌晨 6 点）；  
  
及时获取新型攻击技术情报（如 Exchange 零日利用链）。  
### 6、构建自动化响应与处置能力  
#### （1）SOAR（安全编排自动化响应）  
  
自动提取日志、调用检测脚本、生成报告；  
  
对高风险资产自动隔离、封禁 IP、冻结账户；  
  
设置自动化告警通知（如 Slack、Teams、邮件）。  
#### （2）EDR + XDR 整合  
  
实现终端、网络、邮件、云环境统一检测；  
  
快速定位受害主机，执行远程取证、清除恶意负载；  
  
利用机器学习识别未知威胁行为。  
## （三）实战建议  
<table><tbody><tr><td valign="middle" align="left"><section><span leaf="">攻击阶段</span></section></td><td valign="middle" align="left"><section><span leaf="">防御与发现建议</span></section></td></tr><tr><td valign="middle" align="left"><span style=""><span leaf="">初始入侵</span></span></td><td valign="middle" align="left"><span style=""><span leaf="">监控异常登录、钓鱼邮件、可疑 User-Agent</span></span></td></tr><tr><td valign="middle" align="left"><span style=""><span leaf="">横向移动</span></span></td><td valign="middle" align="left"><span style=""><span leaf="">检查 Kerberos 请求、NTLM 认证、PsExec 等行为</span></span></td></tr><tr><td valign="middle" align="left"><span style=""><span leaf="">持久化</span></span></td><td valign="middle" align="left"><span style=""><span leaf="">查找隐藏的注册表启动项、计划任务、内存马</span></span></td></tr><tr><td valign="middle" align="left"><span style=""><span leaf="">数据外泄</span></span></td><td valign="middle" align="left"><span style=""><span leaf="">检查大流量上传、异常 SMTP 发送、C2 域名通信</span></span></td></tr><tr><td><span style=""><span leaf="">清除痕迹</span></span></td><td><span style=""><span leaf="">审计 Windows 日志完整性、启用 Sysmon 日志记录</span></span></td></tr></tbody></table>  
  
# 四、构建“三位一体”的防御体系  
  
面对 NightEagle APT 这类资源充足的攻击组织，企业需构建“技术+流程+人员 ”三位一体的防御体系：  

```
技术层面 ：部署 EDR/NDR、日志集中管理、威胁情报联动；
流程层面 ：建立应急响应机制、定期红蓝对抗演练；
人员层面 ：加强安全意识培训、提升 SOC 团队攻防能力。
```

  
只有通过主动防御、精准检测、快速响应 ，才能有效应对不断演进的 APT 攻击，保障关键基础设施和核心业务系统的安全稳定运行。  
# 五、参考资料  

```
1、独家披露美国APT组织”夜鹰”攻击活动.pdf
2、https://bbs.360.cn/thread-16164186-1-1.html
3、https://mp.weixin.qq.com/s/Zjx4rycv1AJep589VHO0aQ
4、https://gbhackers.com/nighteagle-apt-unleashes-custom-malware/
5、https://rri.co.id/index.php/iptek/1631839/keberadaan-kelompok-ancaman-siber-tingkat-tinggi-terungkap
```

  
  
