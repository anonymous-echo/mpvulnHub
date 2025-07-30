#  CNNVD | 关于Apache OpenOffice参数注入漏洞情况的通报   
 中国信息安全   2023-03-31 17:47  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1brjUjbpg5xibxLGIogzakEcw0xDJBxvr6Bezc08QAUpZjCTaibbWT6TPzOfwOAa5keLicJFKFekkNibStsB9LtJ7g/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1brjUjbpg5xibxLGIogzakEcw0xDJBxvr6Bezc08QAUpZjCTaibbWT6TPzOfwOAa5keLicJFKFekkNibStsB9LtJ7g/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1brjUjbpg5xibxLGIogzakEcw0xDJBxvrTbTEWf1UibjLspwHagXoQfmT710JUVCT9mflbyTicwIM453Ju70LfHjg/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1brjUjbpg5xibxLGIogzakEcw0xDJBxvr6Bezc08QAUpZjCTaibbWT6TPzOfwOAa5keLicJFKFekkNibStsB9LtJ7g/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1brjUjbpg5xibxLGIogzakEcw0xDJBxvr6Bezc08QAUpZjCTaibbWT6TPzOfwOAa5keLicJFKFekkNibStsB9LtJ7g/640?wx_fmt=gif "")  
  
**扫码订阅《中国信息安全》**  
  
邮发代号 2-786  
  
征订热线：010-82341063  
  
## 近日，国家信息安全漏洞库（CNNVD）收到关于Apache OpenOffice 参数注入漏洞（CNNVD-202303-1952、CVE-2022-47502）情况的报送。成功利用漏洞的攻击者，可在目标系统执行任意代码。Apache OpenOffice 4.1.13及其以下版本均受此漏洞影响。目前，Apache官方已发布新版本修复了该漏洞，建议用户及时确认产品版本，尽快采取修补措施。  
  
**一、漏洞介绍**  
  
Apache OpenOffice是美国阿帕奇（Apache）基金会的一款开源的办公软件套件,该套件包含文本文档、电子表格、演示文稿、绘图、数据库等。由于Apache OpenOffice 文档内可通过含有任意参数的链接调用内部宏，恶意攻击者通过修改特殊URI Scheme 构造恶意链接调用宏，当用户点击链接或通过自动文档事件激活时，会导致覆盖掉文档中现有宏的代码,从而执行任意代码。  
  
**二、危害影响**  
  
成功利用漏洞的攻击者，可在目标系统执行任意代码。ApacheOpenOffice 4.1.13及其以下版本均受此漏洞影响。  
  
**三、修复建议**  
  
目前，Apache官方已发布新版本修复了该漏洞，建议用户及时确认产品版本，尽快采取修补措施。官方下载链接：  
https://www.openoffice.org/download/  
  
本通报由CNNVD技术支撑单位——新华三技术有限公司、上海斗象信息科技有限公司、北京云科安信科技有限公司、天津市兴先道科技有限公司、贵州数创控股（集团）有限公司、内蒙古信息系统安全等级测评中心等技术支撑单位提供支持。  
  
CNNVD将继续跟踪上述漏洞的相关情况，及时发布相关信息。如有需要，可与CNNVD联系。联系方式: cnnvdvul@itsec.gov.cn  
  
（来源：CNNVD）  
  
  
  
  
  
  
**《中国安全信息》杂志倾力推荐**  
  
**“企业成长计划”**  
  
  
**点击下图 了解详情**  
  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzA5MzE5MDAzOA==&mid=2664162643&idx=1&sn=fcc4f3a6047a0c2f4e4cc0181243ee18&chksm=8b5ee7aabc296ebc7c8c9b145f16e6a5cf8316143db3edce69f2a312214d50a00f65d775198d&scene=21#wechat_redirect)  
  
  
