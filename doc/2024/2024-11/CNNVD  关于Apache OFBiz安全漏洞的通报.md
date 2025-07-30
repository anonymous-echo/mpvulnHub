#  CNNVD | 关于Apache OFBiz安全漏洞的通报   
 中国信息安全   2024-11-20 10:12  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1brjUjbpg5yu2TSIxOZGKwVpP76gQo2MfX7ibtlhTaY67PtD9e3t07YjgazE1ND8gGfMic9TdW0piaXVT39EO8JKA/640?wx_fmt=gif&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1brjUjbpg5yu2TSIxOZGKwVpP76gQo2MBicjiae1FlDHspS1icKI5DPchRAiabVUjGwSYgL2zre1AC5ZSd8VdOvFYQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1brjUjbpg5yu2TSIxOZGKwVpP76gQo2MfX7ibtlhTaY67PtD9e3t07YjgazE1ND8gGfMic9TdW0piaXVT39EO8JKA/640?wx_fmt=gif&from=appmsg "")  
  
**扫码订阅《中国信息安全》**  
  
  
邮发代号 2-786  
  
征订热线：010-82341063  
  
  
  
  
  
  
**漏洞情况**  
  
近日，国家信息安全漏洞库（CNNVD）收到关于Apache OFBiz安全漏洞(CNNVD-202411-2279、CVE-2024-47208)情况的报送。攻击者可以利用漏洞向目标发送恶意请求，通过服务端请求伪造的方式远程执行任意代码。Apache OFBiz 18.12.17以下版本受此漏洞影响。目前，Apache官方已发布新版本修复了该漏洞，建议用户及时确认产品版本，尽快采取修补措施。  
  
## 一漏洞介绍  
  
  
Apache OFBiz是美国阿帕奇（Apache）基金会的一套企业资源计划（ERP）系统。该系统提供了一整套基于Java的Web应用程序组件和工具。漏洞源于程序对URL校验不严格，攻击者可通过构造恶意URL绕过校验并注入Groovy 表达式代码或触发服务器端请求伪造（SSRF）攻击，导致远程代码执行。  
  
## 二危害影响  
  
  
Apache OFBiz 18.12.17以下版本受此漏洞影响。  
  
## 三修复建议  
  
  
目前，Apache官方已发布新版本修复了该漏洞，建议用户及时确认产品版本，尽快采取修补措施。官方下载链接如下：  
  
https://ofbiz.apache.org/download.html  
  
本通报由CNNVD技术支撑单位——北京神州绿盟科技有限公司、深信服科技股份有限公司、西安交大捷普网络科技有限公司、数字新时代（山东）数据科技服务有限公司、安恒愿景（成都）信息科技有限公司、网宿科技股份有限公司等技术支撑单位提供支持。  
  
CNNVD将继续跟踪上述漏洞的相关情况，及时发布相关信息。如有需要，可与CNNVD联系。  
  
联系方式：cnnvd@itsec.gov.cn  
  
（来源：CNNVD）  
  
  
  
**分享网络安全知识 强化网络安全意识**  
  
**欢迎关注《中国信息安全》杂志官方抖音号**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1brjUjbpg5yu2TSIxOZGKwVpP76gQo2M2F0GT7xiboynjVmCL5sOibaNp9GaEQxpA1KBZ2HZgaxXibOHG8Uz5ItDQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**《中国信息安全》杂志倾力推荐**  
  
**“企业成长计划”**  
  
  
**点击下图 了解详情**  
  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzA5MzE5MDAzOA==&mid=2664162643&idx=1&sn=fcc4f3a6047a0c2f4e4cc0181243ee18&chksm=8b5ee7aabc296ebc7c8c9b145f16e6a5cf8316143db3edce69f2a312214d50a00f65d775198d&scene=21#wechat_redirect)  
  
  
