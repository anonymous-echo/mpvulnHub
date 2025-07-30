> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651324992&idx=3&sn=2ef9f5b48a5e4cc585fa2555af0fd05f

#  Git CLI高危任意文件写入漏洞曝光，PoC已公开  
 FreeBuf   2025-07-16 10:31  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibCbuTG6icJiajjUCSoQJ1QzFlSbNLz3wKibNGLk90t0jfssVicfEhBxZO54Ytb9ialDwkpfLosKvAwfPA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
Git CLI存在一个高危漏洞，攻击者可利用该漏洞在Linux和macOS系统上实现任意文件写入。目前该漏洞的概念验证（PoC）利用代码已公开。  
  
  
该漏洞编号为CVE-2025-48384，CVSS严重性评分为8.1分。当用户执行  
  
git clone --recursive命令克隆恶意仓库时，攻击者可借此实现远程代码执行。  
  
  
**Part01**  
## 漏洞技术细节  
  
  
据安全研究员Matt Muir和Linux Malware团队披露，CVE-2025-48384漏洞源于Git在处理类UNIX系统上的.gitmodules文件时，对配置值和回车符（\r）字符的基础性解析缺陷。  
  
  
该漏洞的根本原因是Git在读取和写入包含控制字符的配置值时存在关键性不一致。当攻击者构造一个子模块路径以回车符结尾的恶意.gitmodules文件时，Git的配置解析器会在读取操作时剥离该字符，但在写入操作时却保留该字符。  
  
  
这种解析不一致性导致子模块内容可被恶意重定向至任意文件系统位置。该漏洞特别影响macOS和Linux平台上未打补丁的Git CLI版本（v2.43.7、v2.44.4、v2.45.4、v2.46.4、v2.47.3、v2.48.2、v2.49.1和v2.50.1之前的版本）。值得注意的是，由于非UNIX系统在控制字符处理上的根本差异，Windows系统不受此漏洞影响。  
  
  
![image](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibCbuTG6icJiajjUCSoQJ1QzFY0PHayKf0l1NHtlcFwI6DSc81mbENwjDVltQ1XUB1maqAXW2PXSxtg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
macOS平台的GitHub Desktop客户端尤其容易受到攻击，因为它在底层默认执行 git clone --recursive 操作。DataDog研究人员已发现多种利用该任意文件写入原语实现持久性远程代码执行的攻击路径。  
  
  
最常见的攻击场景涉及武器化仓库：攻击者发布带有README说明的仓库，诱导用户执行 git clone --recursive 命令——这种做法在开源项目中经常被推荐使用。一旦克隆了恶意仓库，攻击者就能将仓库子模块中包含的Git Hook脚本直接写入受害者的.git子目录中。  
  
  
这些恶意负载会在常规Git操作（如 git commit 和 git merge 命令）时自动执行，为攻击者提供透明的持久化机制。其他利用技术还包括覆盖受害者的Git配置文件，修改[remote "origin"]部分，从而将知识产权和专有源代码秘密外泄至攻击者控制的服务器。  
  
  
安全研究人员已验证了可向/tmp目录实现任意写入的概念验证利用代码，相关代码已在互联网公开。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibCbuTG6icJiajjUCSoQJ1QzF5Jv3QMoNurriaokKxCh90DZDmyHCmjpoGvqzFs7h6AIoEMd9DAMp32Q/640?wx_fmt=jpeg&from=appmsg "")  
##   
  
**Part02**  
## 修复建议  
  
  
企业必须立即通过各自的包管理器将受影响的Git CLI升级至已修复版本（v2.43.7、v2.44.4、v2.45.4、v2.46.4、v2.47.3、v2.48.2、v2.49.1或v2.50.1）。用户可通过执行git --version命令验证当前Git版本，并与存在漏洞的版本范围（包括v2.50.0、v2.49.0、v2.48.0-v2.48.1、v2.47.0-v2.47.2、v2.46.0-v2.46.3、v2.45.0-v2.45.3、v2.44.0-v2.44.3以及v2.43.6及更早版本）进行比对。  
  
  
macOS平台的GitHub Desktop用户应暂时避免使用该客户端进行Git操作，转而使用已打补丁的Git CLI进行仓库管理，直至官方发布修复补丁。  
  
  
安全团队可实施检测机制，使用自定义代理规则监控针对外部仓库的可疑  
  
git clone --recursive操作，同时在克隆不受信任的仓库前审计.gitmodules文件内容。  
  
  
**参考来源：**  
  
PoC Exploit Released for High-Severity Git CLI Arbitrary File Write Vulnerability  
  
https://cybersecuritynews.com/cli-arbitrary-file-write-vulnerability/  
  
  
###   
###   
###   
  
**推荐阅读**  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651324846&idx=2&sn=0751255f1f80386d498c5f17dc100c06&scene=21#wechat_redirect)  
  
### 电台讨论  
  
****  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
   
  
