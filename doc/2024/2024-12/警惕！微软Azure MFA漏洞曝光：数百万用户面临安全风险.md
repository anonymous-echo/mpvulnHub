#  警惕！微软Azure MFA漏洞曝光：数百万用户面临安全风险   
 安全客   2024-12-16 09:51  
  
最近，Oasis Security的研究团队揭示了一个严重的漏洞，影响了微软Azure的多因素身份验证（MFA）系统，可能使数百万用户的敏感信息面临被攻击的风险。该漏洞允许攻击者在没有用户交互或通知的情况下，轻松获得对Outlook电子邮件、OneDrive文件、Teams聊天和Azure云服务的未经授权访问。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Ok4fxxCpBb4oc1JLtvdzUvEltxON0ial79HhO5lAeTsE1Zh6QaiblApsu6qstCAuYpk18T4vI5QUybZ66zKIgA2w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
该漏洞利用了基于时间的一次性密码（TOTP）实施中的几个关键弱点。Oasis的研究表明，  
微软Azure MFA系统存在以下问题：  
  
  
  
**缺乏速率限制：**Oasis团队发现，微软的系统未能有效限制尝试次数，攻击者可以快速创建新会话并枚举代码，迅速尝试6位代码的所有组合。这种缺乏适当节流的情况使得攻击者能够在短时间内进行大量尝试。  
  
  
**延长的代码有效性窗口：**通常情况下，TOTP代码的有效期为30秒，但微软的系统却允许大约三分钟的容忍窗口。这一延长的有效性窗口使得攻击者有更多时间进行暴力破解，显著提高了成功猜测有效代码的几率。  
  
  
**隐蔽的攻击方式：**Oasis Security指出，该攻击方法简单且隐蔽，攻击者只需约一个小时即可完成攻击，且不会产生任何用户通知或警告。  
  
  
根据Oasis的报告，攻击者在约70分钟内成功猜测代码的概率高达50%。这一时间框架，加上攻击的隐蔽性，使得许多企业和个人用户在不知情的情况下，可能已经面临数据泄露或账户被盗的风险。  
  
  
在发现该漏洞后，微软迅速采取措施修复这一问题。虽然具体的技术细节仍然保密，但微软已引入了更严格的速率限制，以防止此类攻击的发生。根据报告，新的速率限制将在多次失败尝试后生效，并持续约半天，从而有效降低了攻击者的成功率。  
  
  
对于使用微软Azure服务的用户和企业来说，及时更新安全设置和监控账户活动至关重要。建议用户启用额外的安全措施，如使用硬件安全密钥或其他形式的身份验证，以增强账户的安全性。此外，定期审查和更新安全策略，确保能够及时应对潜在的安全威胁。  
  
  
文章来源：  
  
https://securityonline.info/critical-microsoft-azure-mfa-bypass-exposed-what-you-need-to-know/  
  
  
**推荐阅读**  
  
  
  
  
  
<table><tbody><tr><td colspan="1" rowspan="1" style="border-color: rgb(62, 62, 62);border-style: none;" width="100.0000%"><section><section style="display: flex;flex-flow: row;margin-top: 10px;margin-right: 0%;margin-left: 0%;justify-content: flex-start;"><section style="display: inline-block;vertical-align: middle;width: auto;min-width: 10%;height: auto;flex: 0 0 auto;align-self: center;box-shadow: rgb(0, 0, 0) 0px 0px 0px;"><section style="font-size: 14px;color: rgb(115, 215, 200);line-height: 1;letter-spacing: 0px;text-align: center;"><p><strong>01</strong></p></section></section><section style="display: inline-block;vertical-align: middle;width: auto;flex: 100 100 0%;align-self: center;height: auto;"><section style="font-size: 14px;letter-spacing: 1px;line-height: 1.8;color: rgb(140, 140, 140);"><p style=""><span style="color: rgb(224, 224, 224);">｜</span><span style="font-size: 12px;"><a target="_blank" href="https://mp.weixin.qq.com/s?__biz=MzA5ODA0NDE2MA==&amp;mid=2649787610&amp;idx=1&amp;sn=95a8903a00d204b2f0a97e8c4b9362d9&amp;scene=21#wechat_redirect" textvalue="斯柯达汽车漏洞披露" linktype="text" imgurl="" imgdata="null" data-itemshowtype="0" tab="innerlink" data-linktype="2" hasload="1" style="outline: 0px;color: var(--weui-LINK);cursor: default;font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;letter-spacing: 1px;background-color: rgb(255, 255, 255);"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 12px;">斯柯达汽车漏洞披露</span></a></span></p></section></section></section><section style="margin: 5px 0%;"><section style="background-color: rgb(224, 224, 224);height: 1px;"><svg viewBox="0 0 1 1" style="float:left;line-height:0;width:0;vertical-align:top;"></svg></section></section></section></td></tr><tr><td colspan="1" rowspan="1" style="border-color: rgb(62, 62, 62);border-style: none;" width="100.0000%"><section><section style="display: flex;flex-flow: row;margin-top: 10px;margin-right: 0%;margin-left: 0%;justify-content: flex-start;"><section style="display: inline-block;vertical-align: middle;width: auto;min-width: 10%;height: auto;flex: 0 0 auto;align-self: center;"><section style="font-size: 14px;color: rgb(115, 215, 200);line-height: 1;letter-spacing: 0px;text-align: center;"><p><strong>02</strong></p></section></section><section style="display: inline-block;vertical-align: middle;width: auto;flex: 100 100 0%;align-self: center;height: auto;"><section style="font-size: 14px;letter-spacing: 1px;line-height: 1.8;color: rgb(140, 140, 140);"><p style=""><span style="color: rgb(224, 224, 224);">｜</span><span style="font-size: 12px;"><a target="_blank" href="https://mp.weixin.qq.com/s?__biz=MzA5ODA0NDE2MA==&amp;mid=2649787591&amp;idx=1&amp;sn=e8b66114e6f98d415269d5b8d9f96a37&amp;scene=21#wechat_redirect" textvalue="银狐团伙再出新招，Web漏洞成切入点" linktype="text" imgurl="" imgdata="null" data-itemshowtype="0" tab="innerlink" data-linktype="2" hasload="1" style="outline: 0px;color: var(--weui-LINK);cursor: default;font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 1px;font-size: 14px;background-color: rgb(255, 255, 255);"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 12px;">银狐团伙再出新招，Web漏洞成切入点</span></a></span></p></section></section></section><section style="margin: 5px 0%;"><section style="background-color: rgb(224, 224, 224);height: 1px;"><svg viewBox="0 0 1 1" style="float:left;line-height:0;width:0;vertical-align:top;"></svg></section></section></section></td></tr><tr><td colspan="1" rowspan="1" style="border-color: rgb(62, 62, 62);border-style: none;" width="100.0000%"><section><section style="display: flex;flex-flow: row;margin-top: 10px;margin-right: 0%;margin-left: 0%;justify-content: flex-start;"><section style="display: inline-block;vertical-align: middle;width: auto;min-width: 10%;height: auto;flex: 0 0 auto;align-self: center;"><section style="font-size: 14px;color: rgb(115, 215, 200);line-height: 1;letter-spacing: 0px;text-align: center;"><p><strong>03</strong></p></section></section><section style="display: inline-block;vertical-align: middle;width: auto;flex: 100 100 0%;align-self: center;height: auto;"><section style="font-size: 14px;letter-spacing: 1px;line-height: 1.8;color: rgb(140, 140, 140);"><p style=""><span style="color: rgb(224, 224, 224);">｜</span><span style="font-size: 12px;"><a target="_blank" href="https://mp.weixin.qq.com/s?__biz=MzA5ODA0NDE2MA==&amp;mid=2649787578&amp;idx=1&amp;sn=45f7ac3d09b57206a73485ddf7018382&amp;scene=21#wechat_redirect" textvalue="美防务公司将从战场收集数据训练AI模型" linktype="text" imgurl="" imgdata="null" data-itemshowtype="0" tab="innerlink" data-linktype="2" hasload="1" style="outline: 0px;color: var(--weui-LINK);cursor: default;font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 1px;font-size: 14px;background-color: rgb(255, 255, 255);"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 12px;">美防务公司将从战场收集数据训练AI模型</span></a></span></p></section></section></section><section style="margin: 5px 0%;"><section style="background-color: rgb(224, 224, 224);height: 1px;"><svg viewBox="0 0 1 1" style="float:left;line-height:0;width:0;vertical-align:top;"></svg></section></section></section></td></tr></tbody></table>  
  
  
**安全KER**  
  
  
安全KER致力于搭建国内安全人才学习、工具、淘金、资讯一体化开放平台，推动数字安全社区文化的普及推广与人才生态的链接融合。目前，安全KER已整合全国数千位白帽资源，联合南京、北京、广州、深圳、长沙、上海、郑州等十余座城市，与ISC、XCon、看雪SDC、Hacking Group等数个中大型品牌达成合作。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb4oc1JLtvdzUvEltxON0ial7MQtuE3cUicbBJKKibFhH1QQZgiadZweNGfKrtyoyvIl3IEjvsdnoPGKng/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb4oc1JLtvdzUvEltxON0ial7D4DvfF2TWGXBPiconylsZyHRo8TuHr4QCQicYmMWPQbicCwy5xaFWOf3A/640?wx_fmt=png&from=appmsg "")  
  
**注册安全KER社区**  
  
**链接最新“圈子”动态**  
  
