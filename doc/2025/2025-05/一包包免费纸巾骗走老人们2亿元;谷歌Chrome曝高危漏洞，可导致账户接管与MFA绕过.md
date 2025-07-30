#  一包包免费纸巾骗走老人们2亿元;|谷歌Chrome曝高危漏洞，可导致账户接管与MFA绕过   
 黑白之道   2025-05-17 09:42  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
**一包包免费纸巾骗走老人们2亿元;**  
  
警方披露了一起“专挑老年人下手”的非法集资案件。湖南株洲的李先生偶然得知，有家体检中心可以免费做全面体检。体检后，业务员小王隔三差五就打电话请李先生参与免费讲座，每次都送些纸巾、鸡蛋等小礼品。  
  
不久后，小王声称体检中心要扩大规模，以9%的分红年息诱惑李先生投资入股。李先生没有马上答应，小王也不勉强，仍嘘寒问暖，甚至在李先生住院时专程探望。被热情打动的李先生最终决定投资，瞒着家人1年多陆续投资了20余万元。开始时每月利息按时到账，但五六个月后，却收不到利息了。李先生去体检中心想问问情况，却发现早已人去楼空……  
  
警方调查发现，体检中心的老板颜某因经营不善，动了非法集资的歪念头。他伙同大股东刘某，以免费体检等为诱饵，长期对潜在投资人进行关怀，逐步取得信任之后，再以扩大体检项目经营规模为幌子，夸大宣传公司投资前景，编造话术，误导投资人。这一非法集资骗局最终造成800多人受骗，涉案资金高达2亿多元。警方提醒，凡是承诺高回报、返本付息的投资项目，都要提高警惕！  
  
  
**谷歌Chrome曝高危漏洞，可导致账户接管与MFA绕过**  
  
  
![Chrome浏览器与智能手机](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR393g1IzY1y9evH3Ue7ac4IMkwiahjRCUbASictBU16uzmhuTSA9KvfeEBgjicusSNWfr3MjXEA6NPKnw/640?wx_fmt=jpeg&from=appmsg&wxfrom=13&tp=wxpic "")  
  
  
Chrome用户需立即更新浏览器以修复一个正被利用实施账户接管攻击的高危漏洞。在某些环境下，攻击者甚至能借此绕过多因素认证（MFA，Multi-Factor Authentication）。  
  
  
**Part01**  
### 漏洞详情与紧急修复  
  
  
该漏洞编号为CVE-2025-4664，影响136.0.7103.113之前的所有Chrome版本，是谷歌周三更新中修复的四个漏洞之一。谷歌在公告中仅表示："已知CVE-2025-4664漏洞的利用代码已在野出现"，这解释了为何要打破常规更新周期发布紧急补丁。  
  
  
发现该漏洞的研究人员、Neplox Security的Vsevolod Kokorin在X平台（原Twitter）上详细说明："与其他浏览器不同，Chrome会对子资源请求解析Link头部。问题在于Link头部可设置referrer-policy（引用策略），攻击者通过指定unsafe-url即可捕获完整查询参数。"  
  
  
**Part02**  
### 技术原理与攻击路径  
  
  
Link头部通常用于网站告知浏览器需要预加载的页面资源（如图片）。作为HTTP响应的一部分，它能加速响应时间。但当浏览器根据referrer-policy向第三方服务器请求资源时，Chrome会传输包含安全敏感信息的URL，例如用于身份验证的OAuth流程参数。  
  
  
Kokorin指出："查询参数可能包含敏感数据——在OAuth流程中，这可能导致账户接管。开发者很少考虑通过第三方资源图片窃取查询参数的可能性，使得这种攻击手法有时出奇有效。"  
  
  
OAuth作为无需密码的授权机制，广泛应用于单点登录（SSO）等场景。由于OAuth在MFA之后生效，若攻击者诱骗用户泄露URL中的OAuth令牌，就能绕过MFA保护。  
  
  
**Part03**  
### 潜在威胁与修复建议  
  
  
近期安全厂商已发现多起精心设计的攻击尝试利用此类漏洞。虽然尚不确定是否与谷歌警告的攻击相关，但俄罗斯攻击者很可能利用该漏洞，并可能很快将其应用于勒索软件攻击。  
  
  
除CVE-2025-4664外，本次更新还修复了另一个尚未被利用的关键漏洞CVE-2025-4609，以及两个未详细说明的漏洞。企业用户应尽快升级至以下版本：  
- Windows/Mac：136.0.7103.113/.114  
  
- Linux：136.0.7103.113  
  
企业需根据自身遭受攻击的可能性评估修复优先级。虽然当前风险尚属中等，但鉴于漏洞的潜在危害，建议及时部署补丁。  
  
> **文章来源 ：央视新闻、freebuf******  
  
  
**精彩推荐**  
  
  
  
  
# 乘风破浪|华盟信安线下网络安全就业班招生中！  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzAxMjE3ODU3MQ==&mid=2650575781&idx=2&sn=ea0334807d87faa0c2b30770b0fa710d&chksm=83bdf641b4ca7f5774129396e8e916645b7aa7e2e2744984d724ca0019e913b491107e1d6e29&scene=21#wechat_redirect)  
  
  
# 【Web精英班·开班】HW加油站，快来充电！  
  
  
‍[](http://mp.weixin.qq.com/s?__biz=MzAxMjE3ODU3MQ==&mid=2650594891&idx=1&sn=b2c5659bb6bce6703f282e8acce3d7cb&chksm=83bdbbafb4ca32b9044716aec713576156968a5753fd3a3d6913951a8e2a7e968715adea1ddc&scene=21#wechat_redirect)  
  
  
‍  
# 始于猎艳，终于诈骗！带你了解“约炮”APP  
  
[](http://mp.weixin.qq.com/s?__biz=MzAxMjE3ODU3MQ==&mid=2650575222&idx=1&sn=ce9ab9d633804f2a0862f1771172c26a&chksm=83bdf492b4ca7d843d508982b4550e289055c3181708d9f02bf3c797821cc1d0d8652a0d5535&scene=21#wechat_redirect)  
  
**‍**  
  
  
