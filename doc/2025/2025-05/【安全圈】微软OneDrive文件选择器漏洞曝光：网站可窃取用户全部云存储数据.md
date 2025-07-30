#  【安全圈】微软OneDrive文件选择器漏洞曝光：网站可窃取用户全部云存储数据   
 安全圈   2025-05-29 11:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
2025年5月28日，安全研究机构Oasis Security披露微软OneDrive文件选择器（File Picker）存在重大安全漏洞，数百万用户面临云存储数据遭窃风险。该漏洞允许第三方网站绕过"单文件分享"限制，直接获取用户整个OneDrive的完全访问权限。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylhzJGtyNr0uF4pKS49m8wVFHj1hNsUXebGcJQPictH2Cvz56hN6detiaz4lYpbqC7IA08ZofKib8yqog/640?wx_fmt=png&from=appmsg "")  
### 漏洞机理：权限失控的OAuth黑洞  
  
与谷歌Drive采用精细化的drive.file  
权限（仅限所选文件）不同，微软文件选择器存在两大致命缺陷：  
1. **权限过度扩张**  
即使用户仅选择分享单个文件，系统仍会默认申请Files.ReadWrite.All  
全域权限，导致授权网站可获得用户所有OneDrive文件的读写权。  
  
1. **误导性授权界面**  
当前授权弹窗未明确提示"将开放整个云盘访问"，多数用户会误以为仅授权特定文件。（Dropbox采用的非OAuth私有接口则完全规避此风险）  
  
### 雪上加霜的Token管理乱象  
- **历史版本（6.0-7.2）**  
：通过URL片段或浏览器localStorage明文存储令牌  
  
- **最新版（8.0）**  
：虽改用微软认证库（MSAL），令牌仍以明文存于sessionStorage  
  
- **长期令牌危机**  
：系统可能签发可续期的Refresh Token，若被恶意缓存将导致持续数月的后门访问  
  
### 波及范围：从ChatGPT到企业协作平台  
  
包括但不限于：  
- 智能对话：ChatGPT文件上传功能  
  
- 企业协作：Slack/Trello的文件集成  
  
- 项目管理：ClickUp的云存储对接  
安全专家警告，任何调用OneDrive Picker的网站均可利用此漏洞。  
  
### 微软回应与自救指南  
  
微软官方仅表态"未来可能改进"，未给出修复时间表。现建议采取以下应急措施：**个人用户**  
1. 立即前往Microsoft Account隐私设置，撤销可疑应用的"文件读写所有权限"  
  
1. 优先改用"分享链接"功能替代直接授权**企业管理员**  
  
1. 通过条件访问策略（Conditional Access）阻断所有申请Files.ReadWrite.All  
权限的应用  
  
1. 部署云访问安全代理（CASB）监控异常Graph API请求  
  
"这是OAuth权限模型的反面教材——当'读取所有文件'成为默认选项，数据主权便形同虚设。" ——Oasis Security首席研究员  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】全球互联网因BGP协议漏洞出现大规模路由震荡](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069865&idx=1&sn=e29ae988e9c671b37c0b95f70beaf6d5&scene=21#wechat_redirect)  
  
  
  
[【安全圈】警惕！TikTok现新型"点击修复"骗局 黑客利用AI视频传播窃密木马](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069865&idx=2&sn=72bc395534f95c110f7df164dcc3e50c&scene=21#wechat_redirect)  
  
  
  
[【安全圈】数据泄露后阿迪达斯客户的个人信息面临风险](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069865&idx=3&sn=632260e05f05720fa0ac3eee48933542&scene=21#wechat_redirect)  
  
  
  
[【安全圈】Mac 用户遭围攻： 假账本应用程序通过恶意软件窃取加密秘密](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069865&idx=4&sn=e4a034c80ec818af36cf1f001b9f68b9&scene=21#wechat_redirect)  
  
  
  
  
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
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  
