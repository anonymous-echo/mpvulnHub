#  开源CMS TYPO3中存在XSS漏洞   
Adam Bannister  代码卫士   2022-09-16 18:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
易受攻击的开源内容管理系统 (CMS) TYPO3的维护人员修复了位于软件更新中的一个跨站点脚本 (XSS)漏洞。  
  
本周二，GitHhub发布安全公告指出，由于上游包masterminds/html5中存在一个解析问题，导致PHP包typo3/html-sanitizer的XSS机制被绕过， “具有特殊HTML注释的序列中所使用的恶意标记无法被过滤和清理。”  
  
该漏洞已在typo3/cms-core 的7.6.58、8.7.48、9.5.37、10.4.32和11.5.16版本中修复。在此之前的所有版本均受影响。  
  
由于需要用户交互，因此该漏洞被评为“中危”等级，CVSS评分为6.1。尽管如此，尽管TYPO3的市场份额一般，但所代表的活跃安装量非常庞大。该开源CMS在1997年推出，所占的CMS市场份额为2.43%，即客户超过23万人，其中46%位于德国。  
  
TYPO3协会目前拥有900名左右成员，通过捐赠和会员资格订阅的方式支持开发。  
  
该漏洞由安全研究员 David Klein发现，补丁由TYPO3安全团队主管和核心开发人员 Oliver Hader开发。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：  
https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[美国政府发布联邦机构软件安全法规要求，进一步提振IT供应链安全](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513979&idx=1&sn=66625cf062357864cf86053f868d8bb7&chksm=ea948611dde30f0758522e7694b72c9f1abdcbf9c7de8eece909dcdf444e2ce7cf19d357db91&scene=21#wechat_redirect)  
  
  
[Apache开源项目 Xalan-J 整数截断可导致任意代码执行](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513963&idx=4&sn=8f7f84190a33593bda1e3d6c86470af6&chksm=ea948601dde30f178f02bdcc42ac15f052526722f31417ec3cc51f2b92cde6a84be7894c8fe8&scene=21#wechat_redirect)  
  
  
[CSRF防御机制反被CSRF误，csurf 开源NPM包被弃](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513786&idx=2&sn=74891678697b0e36ed3f5b2dfae35425&chksm=ea9487d0dde30ec613ae86e4fd96e0551be1aad357990007323a016cfa483e3249a5b24f75d1&scene=21#wechat_redirect)  
  
  
[黑客马拉松助力雅虎发现数百个Vespa 开源引擎工具的漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513736&idx=1&sn=cf96ec07df04effafc4f1b2e3533a021&chksm=ea9487e2dde30ef4326e4d334f9b3704c01e95fc15a7fa418ec5bc94f5fabc11e579301e7664&scene=21#wechat_redirect)  
  
  
[谷歌推出开源软件漏洞奖励计划，提振软件供应链安全](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513721&idx=1&sn=9ccc0511cb8d6c7134eb54700130f1b7&chksm=ea948713dde30e0503874ed6e5ebcd5a90933ef86048fd21466e73431420b799a861f800164a&scene=21#wechat_redirect)  
  
  
[Linux和谷歌联合推出安全开源奖励计划，最高奖励1万美元或更多](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513617&idx=2&sn=4f50589d2631ebc4ee55cbbb21d52fbd&chksm=ea94877bdde30e6db6623e64b233c7a81ddcaa9a50d7211c608a26c1e48cf51a1ee2101991d5&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://portswigger.net/daily-swig/open-source-cms-typo3-tackles-xss-vulnerability  
  
  
题图：  
Pixabay License  
‍  
  
  
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
