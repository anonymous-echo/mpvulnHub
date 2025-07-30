#  【安全圈】官方强烈建议升级，GitLab又曝严重的账户接管漏洞   
 安全圈   2024-07-11 19:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
7月10日，GitLab警告称，其产品GitLab社区和企业版本中存在一个严重漏洞，允许攻击者以任何其他用户的身份运行管道作业。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaIGjAYuDSicY1zEVhHQmJDfZIfkoGkVGftMkuF0l4KoKImJlvIbApcUexO46vrrXXpicDlD5Dxic3fw/640?wx_fmt=jpeg&from=appmsg "")  
> GitLab DevSecOps平台拥有3000多万注册用户，活跃用户数仅次于 GitHub，超过50%的财富100强公司都在使用该平台，包括T-Mobile、高盛、空客、洛克希德·马丁、英伟达和瑞银。  
  
  
在昨天发布的安全更新中，修补的漏洞被追踪为CVE-2024-6385，CVSS评分为9.6分(满分10分)。它影响所有GitLab CE/EE版本，从15.8到16.11.6，17.0到17.0.4，17.1到17.1.2。  
  
在GitLab尚未披露漏洞某些信息的情况下，攻击者可以利用该漏洞作为任意用户触发新的管道。GitLab管道是一个持续集成/持续部署(CI/CD)系统功能，允许用户自动并行或顺序运行流程和任务，以构建、测试或部署代码更改。  
  
为解决这一严重安全漏洞，GitLab发布了GitLab社区和企业版本17.1.2、17.0.4和16.11.6。该公司强烈建议所有安装运行受以上问题影响的版本尽快升级到最新版本，GitLab.com和GitLab Dedicated已经在运行补丁版本。  
## 账户接管漏洞在攻击中被积极利用  
  
6月底，GitLab修复了一个与CVE-2024-6385几乎相同的漏洞CVE-2024-5655，该漏洞也可能被利用来作为其他用户运行管道。  
  
一个月前，GitLab还修复了一个高严重性漏洞CVE-2024-4835，该漏洞允许未经身份验证的攻击者在跨站点脚本(XSS)攻击中接管帐户。  
  
5月份，CISA发出警告，未经身份验证的攻击者也在积极利用1月份修补的另一个零点击GitLab漏洞CVE-2023-7028通过重置密码来劫持帐户。  
  
今年1月，Shadowserver发现5300多个易受攻击的GitLab实例暴露在网络上，目前仍有不到一半(1795个)的实例可以访问。  
  
攻击者以GitLab为目标，大概率是因为它托管各种类型的企业敏感数据，包括API密钥和专有代码，一旦遭到破坏，托管项目的完整性和机密性将面临重大风险。  
  
这包括供应链攻击，如果威胁行为者在CI/CD(持续集成/持续部署)环境中插入恶意代码，被破坏组织的存储库岌岌可危。  
  
参考来源：  
  
https://www.bleepingcomputer.com/news/security/gitlab-warns-of-critical-bug-that-lets-attackers-run-pipelines-as-an-arbitrary-user/  
  
https://www.darkreading.com/application-security/critical-gitlab-bug-threatens-software-development-pipelines  
  
  
END  
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dkwuWwLoRK9LecmctJ7PZpjbm5yykVQrEXCibr50aWRdf0h4Uamm346mvDtM75rhGibYM8MwCHaKIV4nArRspYpA/640?wx_fmt=other "")  
[【安全圈】不正当抓取高德地图“拥堵延时指数”，被判赔偿1250万](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062714&idx=1&sn=83d0f85beffb166e77ceaaf9ce257782&chksm=f36e6fbac419e6acf95105a083618935cf06c9d6025e58fe5b5fa1f7a651e660c4c233cb4f08&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliav1dicSq0RTRo5q3UVhSGKmKcQ6WEhiaogw7064u8KQmLRtDPvxoaeD4RSTpth9H0jE8RIQh9pj2yw/640?wx_fmt=jpeg "")  
[【安全圈】微软或将为子公司违规行为支付85亿美元罚款](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062714&idx=2&sn=a9a7dcf36577f8f2205120b6ede0bd8c&chksm=f36e6fbac419e6ac992ffcaa29d5ee680a1b031d14d27b73de2e6a227750da588fb65d0aefe6&scene=21#wechat_redirect)  
           
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliav1dicSq0RTRo5q3UVhSGKmicpBLeXkgibRfEGmq99AYT4nUAjlIU5vltoqEuicnpCS8ZogvqbiaVriaLA/640?wx_fmt=jpeg "")  
[【安全圈】RADIUS身份验证协议惊现三十年的漏洞，CERT呼吁紧急关注](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062714&idx=3&sn=20195cf983f3cb8215a3c59511a3f685&chksm=f36e6fbac419e6ac6dd5872ae812a5d462a0164587076598f58f31f5cb9708a782b2174af7e1&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliav1dicSq0RTRo5q3UVhSGKm5aiaNTtQds9kIftAEuOZmbunecs9vCBJNY1NHB4xlusX9P66H4GM9cQ/640?wx_fmt=jpeg "")  
[【安全圈】新型APT组织CloudSorcerer瞄准俄罗斯政府](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062714&idx=4&sn=02aa0946b5fd9def74c5cc4fafc38175&chksm=f36e6fbac419e6ac581247e05b51d297045e851930d2603dae2a9f8e5055eb0d6e50025af05d&scene=21#wechat_redirect)  
            
  
  
  
  
  
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
  
