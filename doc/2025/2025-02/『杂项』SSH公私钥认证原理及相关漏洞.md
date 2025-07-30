#  『杂项』SSH公私钥认证原理及相关漏洞   
 黑白之道   2025-02-10 01:51  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
## 0x01 前言  
  
随着信息安全意识的提升，SSH  
（Secure Shell）作为一种安全的远程登录协议，被广泛应用于服务器管理、数据传输等领域。SSH  
的核心机制之一是公私钥认证，它相比密码认证更安全，能有效抵御暴力破解和中间人攻击。然而，公私钥认证并非绝对安全，其背后还隐藏着一些潜在的漏洞。本篇文章将深入探讨  
SSH  
公私钥认证的原理，并分析其中可能存在的安全隐患，尤其是其被利用作为服务器后门的风险。  
## 0x02 SSH公私钥认证原理  
### 2.1 SSH公私钥对  
  
**公**  
  
**钥**  
  
  
**用于加密数据，可以公开分享。**  
  
**私**  
  
**钥**  
  
  
**用于解密数据，必须保密。**  
  
在SSH  
连接中，客户端持有私钥，服务器持有客户端的公钥。只有持有对应私钥的客户端才能成功认证，确保通信的安全性。  
### 2.2 SSH认证流程  
  
（1）**生成密钥对**  
：  
在本地机器上，首先生成一对公私钥。执行以下命令：  
```
ssh-keygen -t rsa -b 4096 -C "your_email@example.com"
```  
- **-t rsa**  
  
：指定使用RSA  
算法。  
  
- **-b 4096**  
  
：指定密钥长度为4096  
位，增强安全性。  
  
- **-C "your_email@example.com"**  
  
：为生成的密钥添加注释（通常是你的邮箱）。  
  
执行后，系统将提示你保存密钥的位置：  
```
Generating public/private rsa key pair.
Enter file in which to save the key (/home/your_user/.ssh/id_rsa): 
```  
  
可以直接按 **Enter**  
 使用默认路径（~/.ssh/id_rsa  
）。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/4136w7o9JvfIhEKcicTtwn9wb09piaSHQKyvQicmGJzpMulibLNE8CMagrJzZT7aAaDIGF7cAhsfKMCGMJAuZun6Rw/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
（2）**设置私钥密码**  
：  
系统将提示你为私钥设置密码，这一步是可选的，但建议你设置一个密码来增加私钥的安全性。如果你不想设置密码，可以直接按 **Enter**  
 跳过。  
```
Enter passphrase (empty for no passphrase): 
Enter same passphrase again:
```  
  
此时，密钥对已经生成，包含以下两个文件：  
- **私钥**  
  
：~/.ssh/id_rsa  
（务必妥善保管，不要分享给他人）  
  
- **公钥**  
  
：~/.ssh/id_rsa.pub  
（可以公开分享）  
  
（3）**将公钥上传到服务器**  
：  
  
使用ssh-copy-id  
命令  
  
ssh-copy-id  
 是最简单的上传公钥到服务器的方式，它会自动将公钥添加到服务器的~/.ssh/authorized_keys  
文件中。执行以下命令：  
```
ssh-copy-id username@server_ip
```  
  
替换为你要连接的用户名和服务器IP  
地址。命令执行后，系统会提示你输入远程服务器的密码，输入后，公钥将被上传并配置到服务器。  
  
（4）**测试SSH公钥登录**  
：  
在本地机器上，使用以下命令通过SSH  
公钥登录到远程服务器：  
```
ssh username@server_ip
```  
  
（5）**认证成功**  
：  
服务器验证回应的正确性，认证通过，允许连接。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/4136w7o9JvfIhEKcicTtwn9wb09piaSHQKxriazvFWSw4ae9D7SV68KSrSp7tmYWc7mkC3ibAF2KIDkGlogojbHZVA/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
这种方式避免了在网络上传输密码，提升了安全性。  
### 2.3 公私钥认证的优点  
  
1  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/4136w7o9JvfIhEKcicTtwn9wb09piaSHQKozLbnNQzS7oNTaiawxCsJFhIYNEKicRjc0y6YcKYf3lf6BEmWiaFP0xXA/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**抗暴力破解**  
  
  
即便攻击者获取了公钥，也无法轻易解密私钥。  
  
2  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/4136w7o9JvfIhEKcicTtwn9wb09piaSHQKozLbnNQzS7oNTaiawxCsJFhIYNEKicRjc0y6YcKYf3lf6BEmWiaFP0xXA/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**免密登录**  
  
  
一旦公私钥对成功配置，用户可以免密码登录，大大提升了使用便捷性。  
  
3  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/4136w7o9JvfIhEKcicTtwn9wb09piaSHQKozLbnNQzS7oNTaiawxCsJFhIYNEKicRjc0y6YcKYf3lf6BEmWiaFP0xXA/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**安全性强**  
  
  
即使在不安全的网络中，也能通过非对称加密保障数据安全。  
## 0x03 SSH公私钥认证中的问题及相关漏洞利用  
### 3.1 私钥泄露的风险  
  
虽然公私钥机制本身是安全的，但其安全性依赖于私钥的保密性。一旦私钥被窃取，攻击者可以伪装成合法用户访问服务器。常见的泄露途径包括：  
- **私钥未加密**  
  
：用户生成私钥时，未设置密码保护，导致私钥文件一旦被获取便可直接使用。  
  
- **私钥存储不当**  
  
：私钥文件权限设置不当，其他用户或恶意程序可能读取该文件。  
  
- **恶意软件攻击**  
  
：攻击者通过恶意软件窃取私钥文件。  
  
### 3.2 弱密钥攻击  
  
一些用户在生成密钥对时，选择了过短或弱加密算法的密钥（如  
1024  
位  
RSA  
密钥），这些密钥可能被高级攻击者通过现代计算能力破解。因此，使用强加密算法（如  
2048  
位或更高的  
RSA  
密钥，或者  
ED25519  
密钥）是必不可少的。  
  
解决方案：  
```
1.生成强密钥对：使用ssh-keygen命令生成新的RSA或ECDSA密钥对，并确保密钥对的位数足够长（例如4096位）。

2.部署强密钥：将生成的公钥部署到需要访问的服务器上的~/.ssh/authorized_keys文件中，确保禁用密码登录。

3.配置SSH服务器：编辑/etc/ssh/sshd_config文件，确保以下配置项被设置：

        PasswordAuthentication no：禁止密码认证。

        PermitRootLogin no：禁止root用户通过SSH登录。

        PubkeyAuthentication yes：开启公钥认证。

4.重启SSH服务：在配置修改后，重启SSH服务以应用新的配置。
```  
  
### 3.3 Man-in-the-Middle（中间人）攻击  
  
尽管SSH  
的加密通信机制能有效防止窃听，但如果攻击者能够在首次建立连接时实施中间人攻击，劫持公钥交换的过程，便可能替换公钥，使用户之后的通信被篡改或监控。  
### 3.4 公钥文件污染  
  
服务器上的authorized_keys  
文件存储着客户端的公钥，一旦该文件被恶意篡改或污染，攻击者就可以添加自己的公钥，获得对服务器的访问权限。因此，服务器的文件系统安全和权限管理至关重要。  
### 3.5 老旧SSH协议漏洞  
  
SSH  
协议经历了多个版本的更新，早期版本（如  
SSH-1  
）存在严重的安全漏洞。如果服务器支持不安全的旧版本协议，攻击者可能通过这些漏洞进行攻击。因此，建议使用SSH-2  
版本，该版本修复了许多安全问题。  
### 3.6 edis等未授权漏洞写公钥  
  
1.Redis  
存在弱口令或空密码漏洞。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/4136w7o9JvfIhEKcicTtwn9wb09piaSHQKHQrgP9yxSmygNJxEbVUdNUWkcerFRakwfuFMMjBIUxia3eQxR4kKQ9w/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
2.连接后确定Linux  
系统后依次执行命令：  
```
flushall

config set dir /root/.ssh/

config set dbfilename authorized_keys

ssh-rsa AAAAB3Nza**************HFk= root@hostname   （id_rsa.pub文件内容）

save
```  
  
3.选择连接方式为公钥连接。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/4136w7o9JvfIhEKcicTtwn9wb09piaSHQKCM3xPZTWyNdWjJBgntdCS3k8PCZWXDhpjibcx8tQ39ctHSMOJMOibhrQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
## 0x04 防御措施  
### 4.1 私钥的安全存储  
- **加密私钥**  
  
：生成密钥时为私钥设置密码，以防止私钥文件被直接使用。  
  
- **权限设置**  
  
：确保私钥文件仅对当前用户可读（chmod 600）。  
  
- **硬件密钥存储**  
  
：通过硬件安全模块（如YubiKey）存储私钥，避免私钥存储在易受攻击的硬盘上。  
  
### 4.2 使用强加密算法  
  
确保生成密钥时使用2048  
位以上的RSA  
或更强的加密算法，如ED25519  
密钥。  
### 4.3 第一处定期审查公钥文件  
- **定期检查authorized_keys文件**  
  
：确保没有未经授权的公钥被添加。  
  
- **监控文件变化**  
  
：使用文件完整性检测工具，如Tripwire  
，监控服务器上关键文件（如~/.ssh/authorized_keys  
）的变动。  
  
### 4.4 加强日志审查  
  
定期审查服务器的SSH  
登录日志，排查可疑的登录行为，并设置自动化工具检测异常行为，如频繁的无密码认证登录。  
## 0x05 总结  
  
SSH  
公私钥认证为服务器的安全通信提供了强有力的保障，但它的安全性依赖于私钥的妥善保管和服务器配置的正确性。如果服务器配置不当或被恶意用户利用，SSH  
公私钥认证反而可能成为攻击者打开后门的工具。通过定期审查公钥文件、监控服务器活动以及使用强加密算法，可以有效减少攻击者利用SSH  
后门的机会，进一步提升服务器的安全性。  
  
> **文章来源：宸极实验室**  
  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  
