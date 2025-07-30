#  CNNVD | 关于Apache Tomcat安全漏洞的通报   
 中国信息安全   2025-03-11 17:47  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1brjUjbpg5xmfTFWk44mlQ81v6iaia4k9iaNEa0WhusicPK5uYM1qesf6Gia1y7iaSgzg6zoqZHn6o4jvs7WHL56Tn7w/640?wx_fmt=gif&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1brjUjbpg5xmfTFWk44mlQ81v6iaia4k9ia2Hic9YJatfPMtkBlD7iaDfUPCPrnCWttwZ0eDp9d1wU8FiaNu5qiaEjksg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1brjUjbpg5xmfTFWk44mlQ81v6iaia4k9iaNEa0WhusicPK5uYM1qesf6Gia1y7iaSgzg6zoqZHn6o4jvs7WHL56Tn7w/640?wx_fmt=gif&from=appmsg "")  
  
**扫码订阅《中国信息安全》**  
  
  
邮发代号 2-786  
  
征订热线：010-82341063  
  
  
  
**漏洞情况**********  
  
近日，国家信息安全漏洞库（CNNVD）收到关于Apache Tomcat安全漏洞（CNNVD-202503-1068、CVE-2025-24813）情况的报送。未授权的攻击者能够利用漏洞远程执行恶意代码。Apache Tomcat多个版本均受此漏洞影响。目前，Apache官方已发布新版本修复了该漏洞，建议用户及时确认产品版本，尽快采取修补措施。  
  
## 一漏洞介绍  
  
  
Apache Tomcat是美国阿帕奇（Apache）基金会的一款轻量级Web应用服务器，用于实现对Servlet和JavaServer Page（JSP）的支持。漏洞源于Apache Tomcat反序列化机制未对用户输入进行严格验证，攻击者可通过构造恶意序列化对象绕过安全限制，远程执行恶意代码，进而控制服务器。  
  
****  
## 二危害影响  
  
  
Apache Tomcat 11.0.0-M1至11.0.2版本、10.1.0-M1至10.1.34版本和9.0.0.M1至9.0.98版本均受此漏洞影响。  
  
****  
## 三修复建议  
  
  
目前，Apache官方已发布新版本修复了该漏洞，建议用户及时确认产品版本，尽快采取修补措施。官方参考链接：  
  
https://tomcat.apache.org/security/CVE-2025-24813.html  
  
  
本通报由CNNVD技术支撑单位——上海巨耕信息技术有限公司、南京赛宁信息技术有限公司、奇安信网神信息技术（北京）股份有限公司、中国电信股份有限公司网络安全产品运营中心、北京天下信安技术有限公司、北京安信天行科技有限公司、新基信息技术集团股份有限公司、广东信网数安科技有限公司、北京网藤科技有限公司、星云博创科技有限公司、广西网信信息技术有限公司、深圳融安网络科技有限公司、上海戎磐网络科技有限公司、思而听（山东）网络科技有限公司、远江盛邦(北京)网络安全科技股份有限公司、上海今点软件有限公司、中电智安科技有限公司、广州纬安科技有限公司、广东比特豹科技有限公司、天翼数智科技（北京）有限公司、黑龙江安信与诚科技开发有限公司、杭州安恒信息技术股份有限公司、北京锐服信科技有限公司、内蒙古旌云科技有限公司等技术支撑单位提供支持。  
  
  
CNNVD将继续跟踪上述漏洞的相关情况，及时发布相关信息。如有需要，可与CNNVD联系。  
  
联系方式：cnnvd@itsec.gov.cn  
  
（来源：CNNVD）  
  
  
  
**分享网络安全知识 强化网络安全意识**  
  
**欢迎关注《中国信息安全》杂志官方抖音号**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1brjUjbpg5xmfTFWk44mlQ81v6iaia4k9iaxUsWuqA8jq2DVNz5EicBpsHgpwcuHYmhsE6cNgicNwhFMXbxicia5xJyuA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**《中国信息安全》杂志倾力推荐**  
  
**“企业成长计划”**  
  
  
**点击下图 了解详情**  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MzA5MzE5MDAzOA==&mid=2664162643&idx=1&sn=fcc4f3a6047a0c2f4e4cc0181243ee18&scene=21#wechat_redirect)  
  
  
  
