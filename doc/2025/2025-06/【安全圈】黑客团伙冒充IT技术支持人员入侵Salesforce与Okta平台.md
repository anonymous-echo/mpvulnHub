#  【安全圈】黑客团伙冒充IT技术支持人员入侵Salesforce与Okta平台  
 安全圈   2025-06-08 11:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
黑客  
  
  
**谷歌披露新型云端攻击链：黑客团伙伪装IT支持实施语音钓鱼，瞄准欧美零售、酒店及教育行业**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgicxr3aiaf60xFibD7DNRaMGjibSBNul12myLR86z83bsfT2fHEPcWnax7wEUt5GRQdnxaKI5iaRMGicDw/640?wx_fmt=png&from=appmsg "")  
### 攻击手法升级：利用Salesforce工具+社会工程学窃取数据  
  
谷歌威胁情报团队周三发布报告指出，一个自称“**The Community**  
”（简称**Com**  
）的青少年黑客组织正通过**语音钓鱼（vishing）**  
和恶意软件组合攻击，针对欧美酒店、零售及教育行业的云服务展开数据窃取。该活动被谷歌追踪为**UNC6040**  
，已影响约20家机构。  
#### 核心攻击链解析  
1. **伪装IT支持诱导下载恶意软件**  
  
1. 攻击者首先致电目标企业的员工，冒充技术支持人员，诱骗其安装**Salesforce Data Loader**  
的篡改版本（一款合法的数据导入工具）。  
  
1. 通过电话指导受害者输入所谓的“连接代码”，实际授予攻击者直接访问Salesforce环境的权限，绕过常规安全防护。  
  
1. **横向移动窃取多平台数据**  
  
1. 攻击者利用窃取的凭证在目标网络内横向移动，进一步入侵**Okta**  
（身份认证平台）、**Microsoft 365**  
及企业内部协作工具**Workplace**  
，窃取敏感数据。  
  
1. 谷歌旗下Mandiant团队发现，该组织使用的Okta钓鱼基础设施与其他已知攻击存在关联。  
  
1. **延迟勒索与数据泄露威胁**  
  
1. 部分受害企业在初始入侵数月后才收到勒索要求，暗示UNC6040可能与其他专门从事数据变现的黑客团伙存在合作。  
  
### 攻击溯源与关联团伙  
- **基础设施重叠**  
：谷歌观察到此次攻击使用的服务器与此前归因于UNC6040及“The Com”组织的攻击存在共同特征。  
  
- **Scattered Spider疑似参与**  
：该组织主要由英美青少年黑客组成，曾于5月入侵英国零售巨头**玛莎百货（Marks & Spencer）**  
、**哈罗德百货（Harrods）**  
及**合作社集团（Co-op）**  
，导致服务中断（详见此前报道）。  
  
### 行业与安全机构回应  
- **Salesforce声明**  
：公司表示攻击并非利用系统漏洞，而是通过社会工程学欺骗用户，强调“无证据表明其平台存在技术缺陷”。  
  
- **英国警方预警**  
：英国内政部网络安全官员指出，随着对俄语黑客团伙的打击加剧，英语国家（如美、英、澳）的低技术但高效率的黑客组织正快速崛起。英国国家警察局长委员会网络犯罪部门负责人杰里米·班克斯表示：“这些团伙战术简单但极具破坏性，已成为新的主要威胁。”  
  
### 防御建议  
1. **强化员工培训**  
：警惕冒充IT支持的电话钓鱼，严禁通过电话输入敏感信息或安装软件。  
  
1. **限制工具权限**  
：对Salesforce Data Loader等高危工具实施最小权限访问，并监控异常登录行为。  
  
1. **多因素认证（MFA）**  
：确保Okta、Microsoft 365等平台启用强验证机制，阻断凭证窃取后的横向移动。  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】刑事拘留！江苏一男子破解无人机禁飞限高](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070055&idx=1&sn=8d82fcbefb07cba0ce31b9d2c9ce28da&scene=21#wechat_redirect)  
  
  
  
[【安全圈】奢侈时尚品牌卡地亚遭遇网络攻击 客户数据被泄露](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070055&idx=2&sn=dc80894346d8d9a4dfc2ce2e6dba2198&scene=21#wechat_redirect)  
  
  
  
[【安全圈】热门 Chrome 扩展陷 HTTP 和硬编码密钥双重漏洞](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070055&idx=3&sn=6b9ef71bf3e0c60b87ab26c126ce970f&scene=21#wechat_redirect)  
  
  
  
[【安全圈】阿里云 aliyuncs.com 域名故障导致全国网站访问异常](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070040&idx=1&sn=2607d571d2383520da9725b92d2c9691&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
