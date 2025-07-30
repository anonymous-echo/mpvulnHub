#  渗透测试人员的 Nmap：漏洞扫描   
三沐  三沐数安   2024-12-06 01:00  
  
此文所提供的信息只为网络安全人员对自己所负责的网站、服务器等（包括但不限于）进行检测或维护参考，未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作。利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责。本文所提供的工具仅用于学习，禁止用于其他！！！  
### 介绍  
  
Nmap 脚本引擎 (NSE) 是 Nmap 最有效的功能之一，它允许用户准备和共享脚本，以自动执行涉及网络的众多任务。众所周知，Nmap 的速度和能力，它允许并行执行这些脚本。根据用户的需求，他们可以从可用脚本范围中进行选择，也可以根据要求创建自己的脚本。  
  
那么，让我们开始列出所有可用于发现漏洞的脚本。在这里我们看到了可用于检测漏洞的脚本列表。我们将逐一运行这些脚本并检查漏洞。  
```
cd /usr/share/nmap/scripts/
ls -al *vulns*
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8hca51icpLzib2Hb8IlH9bXkAIJHdHAiaXFt3iaBtA1KEsgIk8r7WGthXon0lNoIsMVvxbIhudiboNH0kw/640?wx_fmt=png&from=appmsg "")  
### ms17-010 漏洞  
  
此脚本检测 Microsoft 系统中的 SMBv1 服务器是否容易受到远程代码执行的攻击，该漏洞通常称为**EternalBlue 漏洞**。此漏洞已被 WannaCry 等勒索软件广泛利用。此脚本适用于 Windows XP、2003、7、8、8.1、10 和服务器 2008、2012 和 2016。  
  
您会看到，在执行此脚本时，系统容易受到本质上具有高风险的漏洞的攻击。  
```
nmap --script smb-vuln-ms17-010.nse 192.168.1.16
```  
  
### Vsftpd 后门  
  
该脚本通过尝试使用有害命令利用后门来检查**vsFTPd 2.3.4 后门****漏洞**是否存在。  
```
nmap --script ftp-vsftpd-backdoor -p 21
```  
  
### SSL-Poodle 漏洞  
  
SSL Poodle 是一种中间人攻击，其目的是利用在 SSL 上运行的安全软件。运行此脚本后，您会发现系统存在漏洞。  
```
nmap –script ssl-poodle 192.168.1.12
```  
  
### Rmi 类加载器漏洞  
  
此脚本检查 Java rmiregistry 是否允许类加载。rmiregistry 具有默认配置，允许从远程 URL 加载类，这可能导致远程代码执行。  
```
nmap --script=rmi-vuln-classloader -p 1099 192.168.1.12
```  
  
### HTTP Slowloris 漏洞  
  
它会检查 Web 服务器 Slowloris DoS 攻击中的漏洞，但不会发起实际的 DoS 攻击。此脚本将打开 2 个单独的服务器连接，然后以基本配置请求 URL。  
```
nmap –script http-slowloris-check 192.168.1.12
```  
  
### SSL-CCS 注入  
  
此脚本运行时会检查服务器是否容易受到 SSL/TLS“CCS 注入”漏洞的攻击。要使用 MITM（中间人攻击）利用此漏洞，攻击者将等待新的 TLS 连接，随后客户端和服务器之间会发送“Hello”握手消息。  
```
nmap –script ssl-ccs-injection -p 5432 192.168.1.12
```  
  
### Nmap 漏洞  
  
**Nmap – Vulners**是一个 NSE 脚本，使用一些知名服务来提供有关漏洞的信息。此脚本完全依赖于有关软件版本的信息，因此可与**-sV**标志配合使用。  
  
您可以使用 git hub 代码安装它。然后更新 NSE 数据库中的脚本。  
```
git clone https://github.com/vulnersCom/nmap-vulners /usr/share/nmap/scripts/vulners
nmap --script-updatedb
```  
  
  
让我们加载脚本并使用 nmap vulners 检查目标机器上可用的服务版本。在这里我们看到所有脚本都已加载，可用于基于特定服务版本进行漏洞检测。  
```
nmap -sV -Pn 192.168.1.12 --script=vulners/vulners.nse
```  
  
  
### 结论  
  
因此，我们看到使用 nmap 脚本我们可以检测系统中存在的漏洞，这对渗透测试人员来说是一个好处。  
  
  
