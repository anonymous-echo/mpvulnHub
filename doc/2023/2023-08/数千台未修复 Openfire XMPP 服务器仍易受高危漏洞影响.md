#  数千台未修复 Openfire XMPP 服务器仍易受高危漏洞影响   
THN  代码卫士   2023-08-28 18:15  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
****  
**VulnCheck 公司发布报告称，数千台 Openfire XMPP 服务器仍未修复最近发现的一个高危漏洞 (CVE-2023-32315)。该漏洞评分为7.5，与 Openfire 管理员控制台中的一个路径遍历漏洞有关，可导致未认证攻击者访问为权限用户预留的受限制页面。**  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQxCsB8on33hRFs4GBpWjvm6kyW7FLqmdlOJibZ3JiavFUU6A2LQlrcRQXpxnfSzeYE8RnVRvlWPKibg/640?wx_fmt=png "")  
  
  
该漏洞影响自2015年4月发布的3.10.0以来的所有 Openfire 版本。该漏洞已由软件开发者 Ignite Realtime 在今年5月份发布的版本 4.6.8、4.7.5和4.8.0中修复。  
  
维护人员在一份详细的安全公告中提到，“已部署路径遍历防护措施应对这类攻击，但并不防御某些UTF-16字符的非标准URL编码，这些字符不受当时使用的嵌入式 web 服务器的支持。嵌入式 web 服务器的后续升级包括支持对 UTF-16 字符的非标准 URL 编码。在 Openfire 中部署的路径遍历防护措施并未更新包含对该新编码的防护措施。”  
  
因此，威胁行动者可滥用该弱点绕过对管理员控制台页面的认证要求。该漏洞已遭在野活跃利用，如遭与 Kinsing 密币僵尸网络恶意软件关联的攻击者的攻击等。  
  
Shodan 搜索发现，超过6300台 Openfire 服务器可经由互联网访问，约50%的服务器在受影响的开源XMPP解决方案上运行。  
  
虽然公开的exp 利用该漏洞创建管理员账户、登录并上传插件以实现代码执行，但 VulnCheck 表示可在无需创建管理员账户的前提下实现代码执行，使得攻击更为隐秘。  
  
安全研究员 Jacob Baines 详细说明了现有 exp 的运营模式，表示，“创建管理员账户，获得对 Openfire Plugins 接口的访问权限。该插件系统可使管理员通过已上传的 Java JARs 向 Openfire 或多或少地增加任意功能。很显然这是从认证绕过转向远程代码执行的位置。”  
  
VulnCheck 建议的噪音较少的方法是利用用户较少的方法，访问 “plugin-admin.jsp” 页面，提取 JSESSIONID 和 CSRF 令牌，接着通过 POST 请求上传 JAR 插件。Baines 指出，“在没有认证的情况下就会接受并安装该插件。之后可在无需认证的情况下通过该遍历漏洞，访问 web shell。这种方法将登录尝试离开审计日志并阻止‘已上传插件’通知被记录。由于它在安全审计日志中没有留下任何证据，因此非常重要。”该公司指出，觉察恶意行为的迹象是 openfire.log 文件中捕获的日志可被攻击者利用CVE-2023-32315删除。  
  
鉴于该漏洞已遭实际利用，因此建议用户快速更新至最新版本，抵御潜在威胁。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[PaperCut高危漏洞可使未修复服务器受RCE攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517335&idx=1&sn=fb6f828cad2dd147b64eb18c25e34e7b&chksm=ea94b5fddde33ceb6bbdf2cd3e5cda0f1103d555edec4b0e6008b76a45ecf4d51beda67e6305&scene=21#wechat_redirect)  
  
  
[未修复的 Apache Tomcat 服务器传播 Mirai 僵尸网络恶意软件](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517295&idx=1&sn=7f61402b12fbd46cb399a19ff93ca28e&chksm=ea94b505dde33c13b5e70aa9fdbdf02fc8dc58ac05568e19c5af6385458348da2464e9fa4c8b&scene=21#wechat_redirect)  
  
  
[P2PInfect 蠕虫利用 Lua 沙箱逃逸满分漏洞攻击 Redis 服务器](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517155&idx=3&sn=99559d56c27bee18a974051b96af05ae&chksm=ea94b289dde33b9f3a7595fb90b08a2bae25dc55c979c015f7c97232efdaf810b6fc478d2269&scene=21#wechat_redirect)  
  
  
[vCenter 服务器漏洞可导致代码执行和认证绕过](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516818&idx=1&sn=1088fe2b36f5e1648053d9005c87f2ca&chksm=ea94b3f8dde33aee090d8160c827cb19fdabb2041da6ed2e472b13cf421105f734ea2276b4d6&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2023/08/thousands-of-unpatched-openfire-xmpp.html  
  
  
题图：  
Pixabay  
 License  
  
****  
**本文由奇安信编译，不代表奇安信观点。转载请注明“转自奇安信代码卫士 https://codesafe.qianxin.com”。**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSf7nNLWrJL6dkJp7RB8Kl4zxU9ibnQjuvo4VoZ5ic9Q91K3WshWzqEybcroVEOQpgYfx1uYgwJhlFQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSN5sfviaCuvYQccJZlrr64sRlvcbdWjDic9mPQ8mBBFDCKP6VibiaNE1kDVuoIOiaIVRoTjSsSftGC8gw/640?wx_fmt=jpeg "")  
  
**奇安信代码卫士 (codesafe)**  
  
国内首个专注于软件开发安全的产品线。  
  
   ![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ5iciaeKS21icDIWSVd0M9zEhicFK0rbCJOrgpc09iaH6nvqvsIdckDfxH2K4tu9CvPJgSf7XhGHJwVyQ/640?wx_fmt=gif "")  
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
