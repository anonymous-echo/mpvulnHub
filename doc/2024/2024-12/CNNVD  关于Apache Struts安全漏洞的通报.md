#  CNNVD | 关于Apache Struts安全漏洞的通报   
 中国信息安全   2024-12-12 09:57  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1brjUjbpg5wgeHFjliar42olr9wwjYJ1uIRhOq0gDre37SCIFhPt2Ly0iazCcQSa5SnSxQ4LAvam7rxK3Kibe6DRQ/640?wx_fmt=gif&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1brjUjbpg5wgeHFjliar42olr9wwjYJ1uDia2iasI6bJl3rC023BNMGYLAlprJv8cu5UYT9TlstNfAykW5I2uIK4A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1brjUjbpg5wgeHFjliar42olr9wwjYJ1uIRhOq0gDre37SCIFhPt2Ly0iazCcQSa5SnSxQ4LAvam7rxK3Kibe6DRQ/640?wx_fmt=gif&from=appmsg "")  
  
**扫码订阅《中国信息安全》**  
  
  
邮发代号 2-786  
  
征订热线：010-82341063  
  
  
  
  
  
  
**漏洞情况******  
  
近日，国家信息安全漏洞库（CNNVD）收到关于Apache Struts安全漏洞（CNNVD-202412-1393、CVE-2024-53677）情况的报送。成功利用漏洞的攻击者，可以操纵文件上传参数来启用路径遍历，进而上传可用于执行远程利用代码的恶意文件。Apache Struts 2.0.0-2.3.37版本、Apache Struts 2.5.0-2.5.33版本、Apache Struts 6.0.0-6.3.0.2版本均受此漏洞影响。目前，Apache官方已发布新版本修复了该漏洞，建议用户及时确认产品版本，尽快采取修补措施。  
  
## 一漏洞介绍  
  
  
Apache Struts是美国阿帕奇（Apache）软件基金会下属的Jakarta项目中的一个子项目，是一个基于MVC设计的Web应用框架。漏洞源于Apache Struts中的文件上传模块存在逻辑缺陷导致，未经授权的攻击者可以操纵文件上传参数来启用路径遍历，进而上传可用于执行远程利用代码的恶意文件，启用了FileUploadInterceptor 模块的应用受此漏洞影响。  
  
## 二危害影响  
  
  
Apache Struts 2.0.0-2.3.37版本、Apache Struts 2.5.0-2.5.33版本、Apache Struts 6.0.0-6.3.0.2版本均受此漏洞影响。  
  
## 三修复建议  
  
  
目前，Apache官方已发布新版本修复了该漏洞，建议用户及时确认产品版本，尽快采取修补措施。官方升级链接：  
  
https://struts.apache.org/download.cgi  
  
本通报由CNNVD技术支撑单位——深信服科技股份有限公司、北方实验室（沈阳）股份有限公司、贵州蓝天创新科技有限公司、道普信息技术有限公司、塞讯信息技术（上海）有限公司等技术支撑单位提供支持。  
  
CNNVD将继续跟踪上述漏洞的相关情况，及时发布相关信息。如有需要，可与CNNVD联系。  
  
联系方式：cnnvd@itsec.gov.cn  
  
（来源：CNNVD）  
  
  
  
**分享网络安全知识 强化网络安全意识**  
  
**欢迎关注《中国信息安全》杂志官方抖音号**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1brjUjbpg5wgeHFjliar42olr9wwjYJ1uoooXibakjQOias4yb2dNbCqIABIOTLoJLCTJ6ibRB6pplYdU3EZYIIFpg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**《中国信息安全》杂志倾力推荐**  
  
**“企业成长计划”**  
  
  
**点击下图 了解详情**  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MzA5MzE5MDAzOA==&mid=2664162643&idx=1&sn=fcc4f3a6047a0c2f4e4cc0181243ee18&scene=21#wechat_redirect)  
  
  
  
  
