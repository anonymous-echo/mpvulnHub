#  【安全圈】GitLab 曝出严重漏洞，可能导致任意 CI/CD 管道执行   
 安全圈   2024-10-12 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhop44vsRWpfyDxWRNAbcEfvDnlicK8FMDL0WjdhN6UNNvJCt8VfIk06drjEYt88A4icboFJtcU4Cuw/640?wx_fmt=jpeg&from=appmsg "")  
  
近日，GitLab 发布了社区版（CE）和企业版（EE）的安全更新，以解决八个安全漏洞，其中包括一个可能允许在任意分支上运行持续集成和持续交付（CI/CD）管道的关键漏洞。该漏洞被跟踪为 CVE-2024-9164，CVSS 得分为 9.6（满分 10 分），攻击者可以在某些情况下以任意用户身份触发Pipeline，可能导致权限提升或执行恶意操作 。  
  
GitLab 在一份公告中说："在 GitLab EE 中发现了一个漏洞，影响了从 12.5 开始到 17.2.9 之前的所有版本、从 17.3 开始到 17.3.5 之前的所有版本，以及从 17.4 开始到 17.4.2 之前的所有版本。目前，GitLab CE/EE 17.1.7，17.2.5，17.3.2及以上版本已修复该漏洞。  
  
在其余七个问题中，四个被评为严重程度高，两个被评为严重程度中，一个被评为严重程度低：  
- CVE-2024-8970（CVSS 得分：8.2），允许攻击者在某些情况下以其他用户身份触发管道  
  
- CVE-2024-8977（CVSS 得分：8.2），允许在配置并启用产品分析仪表板的 GitLab EE 实例中进行 SSRF 攻击  
  
- CVE-2024-9631 (CVSS score: 7.5)，可导致在查看有冲突的合并请求的差异时速度变慢  
  
- CVE-2024-6530 （CVSS 得分：7.3），由于跨站点脚本问题，当授权新应用程序时，会在 OAuth 页面中注入 HTML  
  
近几个月来，GitLab 不断披露与管道相关的漏洞，该公告是其中的最新进展。  
## 近期历史漏洞回顾  
  
GitLab近期频繁披露与管道相关的漏洞，此次更新只是其中的一部分。  
  
上个月，GitLab修复了另一个关键漏洞（CVE-2024-6678，CVSS得分：9.9），该漏洞允许攻击者以任意用户身份运行管道作业。  
  
此前，GitLab还修补了其他三个类似的缺陷——CVE-2023-5009（CVSS得分：9.6）、CVE-2024-5655（CVSS得分：9.6）和CVE-2024-6385（CVSS得分：9.6）。  
  
尽管目前没有证据表明这些漏洞已被主动利用，但GitLab强烈建议用户将其实例更新至最新版本，以确保系统安全并防范潜在威胁。定期更新和监控是保护关键基础设施免受攻击的重要措施。  
  
GitLab的安全更新反映了当前软件安全环境的动态性，企业需保持警惕并及时响应安全公告，以维护其数字资产的安全。  
  
参考来源：New Critical GitLab Vulnerability Could Allow Arbitrary CI/CD Pipeline Execution (thehackernews.com)  
  
  
  
END  
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhnDHDVAe6opKibJQic1Q8NrGWKyD1Vr2PxuCCFHsPCprh8CE8RDPVkcSibxQR4qNZCAJn8BrwPFrtag/640?wx_fmt=jpeg "")  
[【安全圈】黑客利用YouTube 平台传播复杂的恶意软件](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652065126&idx=1&sn=5562ea141a9e2aae01c0817545e02138&chksm=f36e6126c419e830c29170f797fca667f587ef4f82d3aa31b74ecc9503ee36d582fe8b68aa57&scene=21#wechat_redirect)  
                 
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylhnDHDVAe6opKibJQic1Q8NrG3iazMPAQRqcQavXibiaXdNaEtAwfzouD8tylbrbdcGevJRqpDIYxC3uEg/640?wx_fmt=png "")  
[【安全圈】卡巴斯基在没有任何提示的情况下安装 UltraAV 防病毒软件](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652065126&idx=2&sn=8e9fa30e13fd724b6d2db34ac224e87e&chksm=f36e6126c419e83056327c2b2e0621009032f48e88917827c71e7f101720f22042654c10fdc0&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhnDHDVAe6opKibJQic1Q8NrGgAGjs88iaMaZ6HaOu2rQMMJEt4LVGFRGJ6KSknPm5EJucIjP7c5mQLw/640?wx_fmt=jpeg "")  
[【安全圈】Veeam曝出关键漏洞，勒索团伙趁火打劫利用RCE攻击全球企业](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652065126&idx=3&sn=d8f627407df3a5064e3fae6c93f446fe&chksm=f36e6126c419e8304a11143da2e5ce6177a7d013ffc3145bc83584d1b2fd95d659377fb27f7e&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhnDHDVAe6opKibJQic1Q8NrGJuoNrRQVXpSvjiakxqJNFEePeaomBfvcIwLzL3ekBC4AGXic5Zq91o2Q/640?wx_fmt=jpeg "")  
[【安全圈】0ktapus威胁组织对130多家企业发起网络攻击](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652065126&idx=4&sn=296d8a29a24fc14afa9850218bc8c4f9&chksm=f36e6126c419e830664f5622f56fc512c9bf6fb71b5a39c71d786528702443cf585a427523fa&scene=21#wechat_redirect)  
               
  
  
  
  
  
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
  
  
  
