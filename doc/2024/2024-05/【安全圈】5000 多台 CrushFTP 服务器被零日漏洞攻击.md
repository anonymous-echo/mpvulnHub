#  【安全圈】5000 多台 CrushFTP 服务器被零日漏洞攻击   
 安全圈   2024-05-01 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
0day漏洞  
  
  
****  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljggduEKM5qia5X5VJZicBSoZqAdYSmsHB3TsC04XXAXxdACYpyG9VLBm4BgFBSLtibyiaVKqg7Nw2leA/640?wx_fmt=jpeg&from=appmsg "")  
  
CrushFTP 服务器包含敏感数据并用于文件共享和存储，这使得它们经常成为黑客数据盗窃和勒索软件攻击的目标。  
  
此外，CrushFTP 服务器中的漏洞可能被用来未经授权地访问网络或向连接的系统分发恶意软件。  
  
最近，Silent Push 的研究人员发现，在版本 10.7.1/11.1.0 之前的 CrushFTP 中存在有严重的零日漏洞，标识为 CVE-2024-4040，其 CVSS 评分为 9.8。  
  
**技术分析**  
  
未经身份验证的漏洞允许攻击者通过 Web 界面逃离虚拟文件系统，获取管理员访问权限和远程代码执行功能。  
  
CrushFTP 强烈建议立即进行升级，即使是在 DMZ（隔离区域）部署的情况下也是如此。  
  
研究人员正在监控此漏洞，并利用易受攻击的域、托管服务的 IP 和基础设施填充数据源，并积极利用 CVE-2024-4040 进行早期检测。  
  
Silent Push 每天进行互联网范围内的扫描，利用 SPQL 对数据进行分类，以定位相关的基础设施和内容。  
  
利用 CVE-2024-4040 的信息，已确定了暴露于互联网的 CrushFTP Web 界面可利用的情况。  
  
由此产生的易受攻击的域和 IP 已经被聚集到两个批量数据源中，供企业客户分析受影响的基础设施。  
  
下面，提到了这两个批量数据源：  
  
**·**CrushFTP 易受攻击的域  
  
**·**CrushFTP 易受攻击的 IP  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljggduEKM5qia5X5VJZicBSoZ84HwaicR14VDKCPic27V1ibGlyvJS805YwfIiblVeJsZAjbwEq5iboN03fw/640?wx_fmt=jpeg&from=appmsg "")  
  
SPQL 的核心是一种跨越 90 多个类别的 DNS 数据分析工具。纵观全球范围内，CrushFTP 接口容易受到 CVE-2024-4040 的攻击的国家，大多数位于美国和加拿大，但也有许多可以在南美洲、俄罗斯、亚洲和澳大利亚以及其他地方找到。  
  
企业用户可以下载原始数据，并以 API 端点的形式导出批量数据源，其中列出易受攻击的 CrushFTP 域和 IP。  
  
有了这些信息，安全团队就可以识别其网络中的弱点，并告知用于评估外部危险的风险评分系统。  
  
同时，用于早期检测的源可以实时跟踪入侵尝试，同时记录与这些尝试相关的基础设施，以便可以自动阻止它。  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgYYPO87zyS6JUrFrjFQgkN1u3noTYG6TLVlFTMbzGvRHh95deuGBKI3rwedR7SZtHMLhs7HP32iaw/640?wx_fmt=png&from=appmsg "")  
[【安全圈】警惕网络空间的“谍影重重”！](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652059121&idx=1&sn=1c3cdd306cc64913c8e58d8d423b96a1&chksm=f36e19b1c41990a76bdfe0d21b7cd1319f5bfc3a404cda87dc01ce108d01cc356297b9ca9ba0&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgI2cWAEb0e1veiceDLAKk6SJ2mZiagDsyxLBo3DReZbxOoHCZDzRmu6t8WELGADyH5N8TwK4X5kzDg/640?wx_fmt=png&from=appmsg "")  
[【安全圈】美国大陆航空航天技术公司 475GB 数据泄露](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652059121&idx=2&sn=015facf42bf7839de8df7e3f3bf899e9&chksm=f36e19b1c41990a752ba301067735cc57b3ae3d325c9e2d5f9cbb360edfd188c30ce7d3c0bdd&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaHBAp5iacuZCOvAorSxvo2h8jVBczLNToAw0SKbbyQtQLn3iaUetmFX7cmb5U1cLaYDGjw2zIiaYk4Vg/640?wx_fmt=other "")  
[【安全圈】白俄罗斯网络游击队声称已渗透白俄罗斯安全部门，访问了 8,600 多名员工的人事档案](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652059121&idx=3&sn=1f3e8263979d9b017ae5a4fe92b67381&chksm=f36e19b1c41990a7ddb3963d72908431d7b958ad449196c4459ce0efce2ca5efdd3724f95e69&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljggduEKM5qia5X5VJZicBSoZXI68bbjgiat4ecxzGLU2DjsFQyevl1smhf75w7TiccDicibWzPxykwLpKQ/640?wx_fmt=jpeg "")  
[【安全圈】霍尼韦尔：针对工业组织的 USB 恶意软件攻击变得更加复杂](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652059121&idx=4&sn=26ec37cbe4aeac095b45a44bce447b2e&chksm=f36e19b1c41990a75e0d78f28868cf2f69e637485dce27caedec47a91f436c8a44d601618db3&scene=21#wechat_redirect)  
  
  
  
  
  
  
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
  
