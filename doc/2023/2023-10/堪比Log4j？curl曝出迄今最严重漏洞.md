#  堪比Log4j？curl曝出迄今最严重漏洞   
 关键基础设施安全应急响应中心   2023-10-12 14:59  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaz5iaQYxGogshLXgrcTX3jMT5KdUibpxBUs4rwr3wibEibzfdn2f28oyjCGlWicbWZaQ6H0f18hibdVfQjAxKXXzp8BQ/640?wx_fmt=png "")  
  
本周二，命令行工具curl曝出两个漏洞（CVE-2023-38545、CVE-2023-38546），其中一个是高严重性漏洞。漏洞详细信息将于10月11日星期三发布curl v8.4.0修复版本后公布。（目前最新版本是8.3.0）  
  
受上述漏洞影响的包括curl（命令行工具）和libcurl（客户端URL传输库），两个工具用于通过各种网络协议传输数据。其中curl是一种广泛极其广泛的基础开源软件，用于通过URL传输数据。  
  
根据curl的项目介绍，“curl广泛应用于汽车、电视机、路由器、打印机、音频设备、手机、平板电脑、医疗设备、机顶盒、电脑游戏、媒体播放器，并且是数千种软件应用程序的互联网传输引擎，  
安装量超过200亿，几乎每位互联网用户日常都会用到curl  
。”  
  
周三即将发布的curl v8.4.0版本将修复的两个漏洞的大致信息如下：  
  
- CVE-2023-38545，一个影响libcurl库和curl工具的高严重性漏洞；  
  
- CVE-2023-38546，一个低严重性漏洞，仅影响libcurl。  
  
curl的作者兼首席开发人员Daniel Stenberg表示，这两个漏洞中较严重的一个“可能是curl有史以来最严重的安全漏洞”。  
  
由于Linux系统默认内置curl，因此curl项目方已将漏洞信息通知并共享给各种Linux发行版的开发者，以便他们提前准备补丁/更新，并在curl 8.4.0发布后快速发布。  
  
Stenberg拒绝透露任何漏洞细节，但表示8.4.0版本中没有更改API或ABI。  
  
“即将发布的curl版本中没有API或ABI变化。更新共享libcurl库应该足以解决所有操作系统上的这个问题（漏洞）。”Stenberg指出。  
  
Qualys威胁研究部门的产品经理Saeed Abbasi认为，由于没有API/ABI更改，大大减少了企业安装补丁前的测试和验证工作量，有助于加快补丁修复速度，减少潜在的攻击风险。此外，对于合规性至关重要的行业和项目，无需验证和认证新的（补丁）集成有助于保持对相关法规和标准的合规性，而无需进行新的审计或检查。  
  
但是，由于许多Docker镜像有自己的curl库副本，因此许多都必须重新构建。Docker产品经理Jonathan Roberts建议用户使用Docker Scout在整个容器存储库中查找curl依赖项。  
  
Endor Labs的安全研究员Henrik Plate指出，攻击者需要向存在漏洞的curl/libcurl实例提交URL来利用漏洞。因此在周三的安全更新之前，开发人员应该抢先检索所有curl/libcurl用例并收集重要的上下文信息，特别是正在使用的curl/libcurl版本和特定的用例。上下文信息必须明确输入到curl中的URL是否来自（不受信任的）用户提供的输入，因为攻击者可能有机会提交URL（例如，包含特殊字符或指向攻击者控制的域名）。  
  
因此，缓解漏洞利用风险的措施除了安装补丁，还应限制从不受信任的网络访问存在漏洞的系统。  
  
值得注意的是，安全人员和开发人员面临一个挑战：curl命令行工具可以通过多种不同的方式安装，例如，通过各种Linux发行版使用的yum和apt包管理器，或者更糟糕的是，只需从curl网站下载二进制文件。此类下载和后续执行通常是脚本化的，即Windows批处理文件或Unix shell脚本的一部分，这使得用户很难找到全部用例。  
  
Synopsys高级软件解决方案经理Mike McGuire则警告用户注意“更新陷阱”，因为攻击者很有可能在团队手忙脚乱之际发布隐藏恶意软件的“修复版本”。  
  
Sonatype安全研究员Ax Sharma表示，curl曝出的高严重性漏洞远没有Log4j棘手。因为大多数情况下curl作为命令行程序使用，与操作系统软件包一同分发并作为系统级服务工具提供，这意味着正常的操作系统更新应该能自动处理这个问题。“它与Log4j非常不同，Log4j作为依赖项嵌入，更加底层且没有直接更新功能。”Sharma说道。  
  
**参考链接：**  
  
https://curl.se/download.html  
  
https://www.docker.com/blog/security-advisory-high-severity-curl-vulnerability/  
  
  
  
原文来源：GoUpSec  
  
“投稿联系方式：孙中豪 010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaz5iaQYxGogvC8qicuLNlkT5ibJnwu1leQiabRVqFk4Sb3q1fqrDhicLBNAqVY4REuTetY1zBYuUdic0nVhZR4FHpAfg/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
