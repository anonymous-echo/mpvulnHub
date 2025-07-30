#  【安全圈】需要采取紧急行动：ABB ASPECT 漏洞使建筑物面临网络攻击   
 安全圈   2024-12-09 11:02  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylia8JVTXjJ9sO59BMpC1PK4Rav7DHcD14smblfiaPQX4c2vuxqKT9xl6zwnBZT8egiby7rbDibnicLbziaw/640?wx_fmt=other&from=appmsg "")  
  
ABB 针对其楼宇能源管理平台 ASPECT 系统发布了重要网络安全公告。该公告于2024年12月5日发布，详细描述了多个漏洞，这些漏洞可能允许攻击者远程控制该系统并执行恶意代码。  
  
这些漏洞影响到 ASPECT 的不同版本，包括未经授权的访问和远程代码执行，以及跨站脚本和拒绝服务攻击。ABB 已将 CVSS v3.1 基本分高达 10.0，表明了这些漏洞的严重性。  
  
该公告强调了许多漏洞，包括：  
- CVE-2024-6298 (CVSS 10)：远程代码执行 (RCE)输入验证不当可允许攻击者远程执行任意代码。ABB 指出，“攻击者可以成功利用这些漏洞，远程控制产品，并可能插入和运行任意代码”。  
  
- CVE-2024-6515 (CVSS 9.6)：明文密码密码可能以明文或 Base64 编码处理，增加了意外暴露凭证的风险。  
  
- CVE-2024-51551 (CVSS 10)：默认凭据使用公开默认凭据的设备容易受到未经授权的访问，因此需要立即更新凭据。  
  
- CVE-2024-51549 (CVSS 10)：绝对路径遍历该漏洞可访问和修改非预期资源，带来重大安全风险。  
  
该公告强调，ASPECT 设备的设计并非面向互联网。ABB 重申了之前向客户发出的警告，指出：“ASPECT 设备并非面向互联网。2023 年 6 月发布的产品公告向客户告知了这一参数。”  
  
尽管如此，只有当攻击者能够访问安装了 ASPECT 并直接暴露于互联网的网段时，才能利用本公告中报告的漏洞。  
  
ABB 感谢 Zero Science Lab 的 Gjoko Krstikj 负责任地报告了这些漏洞。公司已发布固件更新来解决这些问题，并敦促客户立即应用这些更新。  
  
为降低风险，ABB 概述了以下即时步骤：  
1. 断开暴露于互联网的设备的连接移除任何直接连接到互联网或配置了不安全网络设置的 ASPECT 系统。  
  
1. 升级固件确保所有 ASPECT 产品更新到 3.08.03 或更新版本，以解决这些漏洞。  
  
1. 实施安全访问控制使用安全的虚拟专用网络（VPN）进行远程访问，并确保防火墙保护 ASPECT 安装。  
  
1. 更改默认凭据ABB强调，安装后立即更改默认密码至关重要。  
  
   END    
  
  
阅读推荐  
  
  
[【安全圈】微软正在修复Windows 11更换主板后无法激活的问题 遇到该问题的用户还需稍等](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652066522&idx=1&sn=5fe191c712fa1ff6d19b3a8265275399&scene=21#wechat_redirect)  
  
  
  
[【安全圈】关键的联发科芯片组漏洞影响15亿手机用户](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652066522&idx=2&sn=e68dc56710af72cb8e044123396dd41a&scene=21#wechat_redirect)  
  
  
  
[【安全圈】非洲执法部门抓获1，000多名网络犯罪嫌疑人](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652066522&idx=3&sn=f789eb868cc22c85f8654971a6850e67&scene=21#wechat_redirect)  
  
  
  
[【安全圈】最强大的Android间谍软件曝光，可提取信息、密码和执行shell命令](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652066522&idx=4&sn=ae11fb62c2a8d008be5f5b29b0d3eb8d&scene=21#wechat_redirect)  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  
  
  
