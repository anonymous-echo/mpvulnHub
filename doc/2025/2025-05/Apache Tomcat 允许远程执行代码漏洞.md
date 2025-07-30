#  Apache Tomcat 允许远程执行代码漏洞   
 网安百色   2025-05-27 11:32  
  
Apache Tomcat 中的一个关键路径等效漏洞（称为 CVE-2025-24813）在概念验证漏洞利用代码公开发布后被广泛利用。  
  
该漏洞于 2025 年 3 月 10 日披露，允许在特定服务器配置下执行未经身份验证的远程代码，并影响全球数百万个基于 Java 的 Web 应用程序。  
  
安全研究人员在漏洞披露后不久就证实了积极的利用尝试，网络安全和基础设施安全局 （CISA） 于 2025 年 4 月 1 日将其添加到已知利用漏洞目录中。  
## CVE-2025-24813：Apache Tomcat 路径等效漏洞  
  
CVE-2025-24813 表示一个路径等效漏洞，它利用了 Apache Tomcat 在内部处理文件路径的方式，特别是影响服务器对部分 PUT 请求的处理和会话文件持久性。  
  
该漏洞影响了广泛的 Apache Tomcat 版本，包括 11.0.0-M1 到 11.0.2、10.1.0-M1 到 10.1.34 以及 9.0.0-M1 到 9.0.98。  
  
此外，Recorded Future 的安全研究人员发现 8.5.x 版本（特别是 8.5.0 到 8.5.98 和 8.5.100，不包括 8.5.99）也容易受到攻击，尽管这些版本并未包含在 Apache 的初始公告中。  
  
该漏洞源于对 HTTP 请求的不当处理，这些请求允许未经授权访问受限目录和敏感文件。  
  
成功利用后，攻击者可以实现远程代码执行、严重信息泄露或恶意内容注入，从而破坏关键的服务器配置文件。  
  
该缺陷特别影响服务器在内部处理文件路径的方式，其中斜杠在 DefaultServlet 的路径映射逻辑中转换为点。  
  
成功利用 CVE-2025-24813 需要一组特定的先决条件，使漏洞在默认配置中不太可能被利用。  
  
该攻击要求将默认 servlet 的 readonly 属性设置为 false，从而允许通过 HTTP PUT 请求进行写入访问，但默认情况下此设置处于禁用状态。  
  
其他要求包括启用部分 PUT 功能、具有默认存储位置的基于文件的会话持久性，以及应用程序中存在易反序列化的库。  
  
攻击方法涉及一个两步过程，攻击者首先使用 PUT 请求将恶意序列化的 Java 负载上传到 /random/session 等路径，Tomcat 在内部将其映射到名为 .random.session 的文件。  
  
随后，攻击者发送一个 GET 请求，其中包含引用恶意会话的特制 JSESSIONID Cookie，从而导致服务器反序列化有效负载并执行任意代码。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1QIbxKfhZo6RCdcUP6h79lk8gl6oesdUeQC1QnU74jjS8htehODd3Vtg0bfpyAtodd0hBY6XzNtcd3cjOFhI2Q/640?wx_fmt=png&from=appmsg "")  
  
  
  
安全研究人员观察到，针对 *.session 文件路径的常见攻击负载具有随机命名方案，该方案由附加了 .session 文件扩展名的六字符基组成。  
  
<table><tbody><tr style="box-sizing: border-box;background-color: rgb(240, 240, 240);"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><strong msttexthash="14330498" msthash="76" style="box-sizing: border-box;font-weight: bold;"><span leaf="">风险因素</span></strong></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><strong msttexthash="3259074" msthash="77" style="box-sizing: border-box;font-weight: bold;"><span leaf="">详</span></strong></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">受影响的产品</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">– Apache Tomcat 11.0.0-M1 到 11.0.2- Apache Tomcat 10.1.0-M1 到 10.1.34- Apache Tomcat 9.0.0.M1 到 9.0.98- 此外：8.5.0 到 8.5.98 和 8.5.100（根据第三方分析）</span></section></td></tr><tr style="box-sizing: border-box;background-color: rgb(240, 240, 240);"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">冲击</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">远程代码执行 （RCE）</span></section></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">利用先决条件</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">1. 默认 servlet 配置为 readonly=“false”（默认处于禁用状态） 2.启用部分 PUT 支持（默认设置） 3.使用默认存储位置的基于文件的会话持久性 4.应用程序中存在易反序列化的库 5.了解内部文件命名约定</span></section></td></tr><tr style="box-sizing: border-box;background-color: rgb(240, 240, 240);"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">CVSS 3.1 分数</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">9.8（严重）</span></section></td></tr></tbody></table>## 概念验证  
  
GitHub 上已经发布了公开的概念验证漏洞利用代码，大大降低了潜在攻击者的门槛。  
  
PoC 演示了完整的攻击链，利用 ysoserial 等工具生成恶意序列化有效负载并执行 whoami 或 curl 等命令进行远程通信。  
  
该漏洞利用代码包括通过 PUT 请求测试服务器可写性的功能，并自动生成用于有效负载交付的会话 ID。  
  
组织必须立即升级到修补版本：Apache Tomcat 11.0.3、10.1.35 或 9.0.99 以解决此漏洞。  
  
其他缓解策略包括禁用不必要的 HTTP 方法、实施严格的访问控制以及部署具有特定规则的 Web 应用程序防火墙 （WAF） 以检测 CVE-2025-24813 漏洞利用尝试。  
  
**免责声明**  
：  
  
本公众号所载文章为本公众号原创或根据网络搜索下载编辑整理，文章版权归原作者所有，仅供读者学习、参考，禁止用于商业用途。因转载众多，无法找到真正来源，如标错来源，或对于文中所使用的图片、文字、链接中所包含的软件/资料等，如有侵权，请跟我们联系删除，谢谢！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vKicbNtIkdNvibicL87FjAOqGicuxcgBuRjjolLcGDOnfhMdykXibWuH6DV1g/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
