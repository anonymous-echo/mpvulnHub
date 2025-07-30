#  谷歌Chrome零日漏洞遭广泛利用，可执行任意代码   
 湖南省网络空间安全协会   2025-06-04 06:54  
  
谷歌在确认攻击者正在广泛利用一个关键零日漏洞（zero-day vulnerability）后，紧急发布了Chrome安全更新。该漏洞编号为CVE-2025-5419，攻击者可通过Chrome V8 JavaScript引擎中的越界读写操作，在受害者系统上执行任意代码。  
  
  
**Part01**  
### 紧急安全更新发布  
  
  
谷歌已向Windows和Mac用户推送Chrome 137.0.7151.68/.69版本，Linux系统版本为137.0.7151.68，更新将在未来数日乃至数周内全球逐步推送。谷歌明确表示"利用CVE-2025-5419漏洞的代码已存在"，将此列为需要用户立即处理的高优先级安全问题。  
  
  
**Part02**  
### 漏洞技术细节  
  
  
该漏洞由谷歌威胁分析小组（Threat Analysis Group）的Clement Lecigne和Benoît Sevens于2025年5月27日发现并报告。漏洞源于Chrome的JavaScript和WebAssembly引擎V8中的内存损坏问题，该引擎负责处理网站和Web应用程序的代码。  
  
  
越界内存访问漏洞尤其危险，攻击者可借此读取敏感数据或将恶意代码写入系统内存。鉴于威胁严重性，谷歌于2025年5月28日实施紧急缓解措施，在所有Chrome平台推送配置变更，在完整补丁发布前为用户提供保护。  
  
  
**Part03**  
### 同步修复的中危漏洞  
  
  
本次安全更新还修复了第二个漏洞CVE-2025-5068，这是Chrome渲染引擎Blink中的释放后使用（use-after-free）缺陷。安全研究员Walkman于2025年4月7日报告了这个中危漏洞，谷歌为此颁发了1,000美元漏洞赏金。虽然严重性低于零日漏洞，但释放后使用漏洞仍可能导致内存损坏和潜在代码执行。  
  
  
**Part04**  
### 谷歌的安全防护机制  
  
  
谷歌坚持在大多数用户完成浏览器更新前限制详细漏洞信息的访问政策，此举可防止恶意行为者在用户仍使用易受攻击版本时，通过逆向工程补丁开发新的利用代码。谷歌将其综合安全测试基础设施归功于能够在漏洞进入稳定版前发现多数问题，开发过程中采用AddressSanitizer、MemorySanitizer、UndefinedBehaviorSanitizer、控制流完整性（Control Flow Integrity）、libFuzzer和AFL等先进工具识别潜在安全问题。  
  
  
**Part05**  
### 用户应对建议  
  
  
Chrome用户应立即通过"设置 > 关于Chrome"更新浏览器，系统将自动下载安装最新版本。鉴于CVE-2025-5419正遭活跃利用，谷歌强烈建议用户将此更新视为紧急事项。用户可检查Chrome版本是否为137.0.7151.68或更高以确保防护。企业应优先在全网部署此更新，防止攻击者通过针对该零日漏洞的恶意网站实施入侵。  
  
（内容来源：  
FreeBuf  
）  
  
编辑：周鸣宇  
  
一审：陈孝兰  
  
终审：邓庭波  
  
END  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wIpLE08cKh7eW42KbUD7QWcok1ib1kZC4PGgLtFJCCLrJlNMaBm5xyshTqiaIJbQicwsusUFxU0X4kfyrYcuAw8hg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
[【活动】集智汇能 共筑安全——湖南省网络空间安全协会专家咨询委员会2023年新春座谈会成功召开](http://mp.weixin.qq.com/s?__biz=MzAwMTg3MDQzOA==&mid=2247506768&idx=1&sn=7e696b7854e80c5c99b0abc48fc8ac3e&chksm=9ad18459ada60d4f1e3faa53fb665084671c0940fbde3d7492a4c21679da1b89c5577c3ad05f&scene=21#wechat_redirect)  
  
  
[【活动】聚势谋远 拓启新篇——湖南省网络空间安全协会2022年度工作会议顺利召开](http://mp.weixin.qq.com/s?__biz=MzAwMTg3MDQzOA==&mid=2247501198&idx=1&sn=e6d5d61109d12bb7fdcc4ec049b820ed&chksm=9ad19a87ada6139132b3c846edf47c57426ac9df5043db0459b09a4b3853da0fec06029b5032&scene=21#wechat_redirect)  
  
  
[【活动】湖南公安机关举办2022年国家网络安全宣传周法治主题日活动](http://mp.weixin.qq.com/s?__biz=MzAwMTg3MDQzOA==&mid=2247495934&idx=1&sn=74561543eb5d4f3a725d247d52d2985f&chksm=9ad1aff7ada626e173176b5818ddff433abbed98eff789e66704f072d205309e5c3c45cdfa09&scene=21#wechat_redirect)  
  
  
[【视频】盘点湖南网络安全这十年视频来啦！速看](http://mp.weixin.qq.com/s?__biz=MzAwMTg3MDQzOA==&mid=2247495934&idx=2&sn=6049cc3c3b04a2eb69f1d25cf4316225&chksm=9ad1aff7ada626e1e0626cf770e4a036ca198f8c2d8d2042d0733a2683fc3833f2e49029dee4&scene=21#wechat_redirect)  
  
  
[【](http://mp.weixin.qq.com/s?__biz=MzAwMTg3MDQzOA==&mid=2247506768&idx=1&sn=7e696b7854e80c5c99b0abc48fc8ac3e&chksm=9ad18459ada60d4f1e3faa53fb665084671c0940fbde3d7492a4c21679da1b89c5577c3ad05f&scene=21#wechat_redirect)  
  
[活动】湖南省2022年工业互联网安全深度行暨网络安全应急演练活动成功举](http://mp.weixin.qq.com/s?__biz=MzAwMTg3MDQzOA==&mid=2247506768&idx=1&sn=7e696b7854e80c5c99b0abc48fc8ac3e&chksm=9ad18459ada60d4f1e3faa53fb665084671c0940fbde3d7492a4c21679da1b89c5577c3ad05f&scene=21#wechat_redirect)  
  
  
[【活动】](http://mp.weixin.qq.com/s?__biz=MzAwMTg3MDQzOA==&mid=2247492497&idx=1&sn=d92c82a0d99d116b064f52a4a867ca4c&chksm=9ad1bc98ada6358ea04cd4876ac1fd5c195ec25b496f87217c89ca81ea04c871f71e49c057a0&scene=21#wechat_redirect)  
  
[我](http://mp.weixin.qq.com/s?__biz=MzAwMTg3MDQzOA==&mid=2247492497&idx=1&sn=d92c82a0d99d116b064f52a4a867ca4c&chksm=9ad1bc98ada6358ea04cd4876ac1fd5c195ec25b496f87217c89ca81ea04c871f71e49c057a0&scene=21#wechat_redirect)  
  
[协会等保专委会2022年第一次工作座谈会成功举行](http://mp.weixin.qq.com/s?__biz=MzAwMTg3MDQzOA==&mid=2247492497&idx=1&sn=d92c82a0d99d116b064f52a4a867ca4c&chksm=9ad1bc98ada6358ea04cd4876ac1fd5c195ec25b496f87217c89ca81ea04c871f71e49c057a0&scene=21#wechat_redirect)  
  
## 【活动】我协会专家咨询委员会2022年工作座谈会召开  
# 【分享】3保1评｜分保、等保、关保、密评之间联系与区别  
## 【活动】我协会2021年度工作会议顺利召开  
  
## 【前瞻】盘点：未来几年网络安全行业重点预测  
## 【协会活动】2021湖南省网络安全宣传周法治日主题活动圆满落幕  
  
## 【协会活动】益阳市网络安全等级保护制度2.0国家标准宣贯会成功举行  
## 【协会活动】岳麓峰会•网络安全主题论坛成功举办  
## 【提醒】公安部通知：96110来电必须要接！附48种常见电信诈骗手法  
## 【安全圈】脑洞大开！史上最离奇的网络攻击事件盘点  
  
  
## 【安全圈】中小型银行实战攻防演练经验分享  
## 【等保】干货|医疗行业等保实战  
## 【等保】等保2.0 | 二、三级系统所需安全设备及常见问题详解  
## 【等保】划重点 | 等保 2.0 “必考题”  
## 【等保】等保2.0丨系统定级指引  
## 【等保】等保2.0 企业关注问题汇总  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/wIpLE08cKh4zkurpHzhdKRicurpwjcAvtS3IguEujicngsjr5RXhXiaabK1ibhzRo9tcRs5sccNZ9UUzAYPbZyTbBA/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/wIpLE08cKh4zkurpHzhdKRicurpwjcAvtS3IguEujicngsjr5RXhXiaabK1ibhzRo9tcRs5sccNZ9UUzAYPbZyTbBA/640?wx_fmt=gif "")  
  
**湖南省网络空间安全协会**  
  
0731-84597382  
  
长按识别二维码关注我们  
  
等保测评 | 培训认证  
  
会议举办 | 行业交流  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/wIpLE08cKh4zkurpHzhdKRicurpwjcAvt9r42crDIbtLHDCUlh4SibreIU7A8OmQorlvoiaqpOibRZBU2mUqfI4zzg/640?wx_fmt=jpeg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/wIpLE08cKh4zkurpHzhdKRicurpwjcAvtS3IguEujicngsjr5RXhXiaabK1ibhzRo9tcRs5sccNZ9UUzAYPbZyTbBA/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/wIpLE08cKh4zkurpHzhdKRicurpwjcAvtS3IguEujicngsjr5RXhXiaabK1ibhzRo9tcRs5sccNZ9UUzAYPbZyTbBA/640?wx_fmt=gif "")  
  
  
  
  
  
