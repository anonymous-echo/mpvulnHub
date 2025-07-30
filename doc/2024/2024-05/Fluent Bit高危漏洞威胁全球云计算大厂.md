#  Fluent Bit高危漏洞威胁全球云计算大厂   
 关键基础设施安全应急响应中心   2024-05-22 14:54  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaz5iaQYxGogsFtwvfV3PKibrve3gVQTxvSaVylBfkPNQ5nlmbUz5AQqicCdFNgFzq3xZ9AA639lo4Wf5Acfiar6pYg/640?wx_fmt=png&from=appmsg "")  
  
Fluent Bit是一个极为流行的开源多平台日志处理器工具，近日曝出高危漏洞，波及全球几乎所有主流云服务商和众多科技巨头。  
  
Fluent Bit不仅兼容Windows、Linux和macOS系统，还嵌入在各大主流Kubernetes发行版中，其中就包括亚马逊AWS、谷歌GCP和微软Azure的产品。截至2024年3月，Fluent Bit的下载部署量已超过130亿次，相比2022年10月报告的30亿次呈现爆炸式增长。  
  
Crowdstrike、趋势科技等网络安全厂商以及思科、VMware、英特尔、Adobe和戴尔等科技公司均在其系统中部署了FluentBit。  
  
Tenable安全研究人员发现此漏洞并将其命名为“CVE-2024-4323-语言伐木工(Linguistic Lumberjack)”，这是一个内存损坏高危漏洞，出现在Fluent Bit嵌入式HTTP服务器解析跟踪请求过程中，版本号则最早可追溯至2.0.7。  
  
未经身份验证的攻击者可以轻松利用此漏洞发动拒绝服务攻击，或远程窃取敏感信息。在具备充分条件和时间的情况下，甚至有可能借此漏洞实现远程代码执行。Tenable表示：“这类堆栈溢出漏洞虽然已知可被利用，但要构建一个可靠的攻击程序不仅困难，而且极其耗时。研究人员认为，该漏洞最紧迫的风险在于易于发起的拒绝服务攻击和信息泄露。”  
  
**修复措施**  
  
Tenable在4月30日向Fluent Bit开发商通报了该安全漏洞，相关修复程序已于5月15日提交至Fluent Bit的主分支。包含漏洞修复的正式版本预计将随Fluent Bit 3.0.4发布（Linux软件包链接：https://github.com/fluent/fluent-bit/actions/runs/9097880110）。  
  
Tenable也于5月15日通过漏洞披露平台通知了微软、亚马逊和谷歌。  
  
对于已经部署Fluent Bit的用户，在官方补丁发布之前，可以通过限制对Fluent Bit监控API的访问（仅授权用户和服务）来降低风险。若非必要，也可以禁用该易受攻击的API端点，以确保潜在攻击被阻断并缩小攻击面。  
  
**参考链接：**  
  
https://www.tenable.com/blog/linguistic-lumberjack-attacking-cloud-services-via-logging-endpoints-fluent-bit-cve-2024-4323  
  
  
  
原文来源：GoUpSec  
  
“投稿联系方式：010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaz5iaQYxGogvC8qicuLNlkT5ibJnwu1leQiabRVqFk4Sb3q1fqrDhicLBNAqVY4REuTetY1zBYuUdic0nVhZR4FHpAfg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
