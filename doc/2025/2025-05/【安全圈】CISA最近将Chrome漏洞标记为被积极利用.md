#  【安全圈】CISA最近将Chrome漏洞标记为被积极利用   
 安全圈   2025-05-20 11:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![Google Chrome](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljROjzsmRXic12iaeThOibENaIpWlMON2USLN90n5a7XqRrFruyMHQxobJgjibjLPJOge38SDFcaQaBvw/640?wx_fmt=jpeg&from=appmsg "")  
  
周四,CISA警告美国联邦机构保护其系统免受利用Chrome网络浏览器中高严重性漏洞的持续攻击。  
  
Solidlab安全研究员Vsevolod Kokorin发现了这个漏洞(CVE-2025-4664),并于5月5日在线分享了技术细节。released security updates谷歌周三发布了安全更新以修补它。  
  
正如Kokorin解释的那样,due该漏洞是由于Google Chrome的Loader组件中策略执行不力,并且成功的利用可以允许远程攻击者通过恶意制作的HTML页面泄漏跨源数据。  
  
你可能知道,与其他浏览器不同,Chrome 会解析子资源请求上的 Link 标头。但问题是什么?问题在于 Link 标头可以设置引用策略。我们可以指定不安全的URL并捕获完整的查询参数,“Kokorin指出。  
  
查询参数可以包含敏感数据,例如,在 OAuth 流中,这可能会导致 Account 接管。开发人员很少考虑通过第三方资源的图像窃取查询参数的可能性。  
  
虽然谷歌没有透露该漏洞以前是否在攻击中被滥用,或者它是否仍在被利用,但它在安全咨询中警告说,它有一个公开的漏洞,这通常是它暗示主动利用的方式。  
### 被标记为被积极利用  
  
一天后,CISA证实CVE-2025-4664在野外被滥用,并将其添加到已知的受剥削脆弱性目录中,该目录列出了在攻击中积极利用的安全漏洞。  
  
根据2021年11月具有约束力的操作指令(BOD)22-01,美国联邦文职行政部门(FCEB)机构必须在6月5日之前在三周内修补其Chrome安装,以保护其系统免受潜在违规行为的影响。  
  
虽然此指令仅适用于联邦机构,但建议所有网络维护者尽快优先修补此漏洞。  
  
“这些类型的漏洞是恶意网络行为者的频繁攻击媒介,对联邦企业构成重大风险,”网络安全机构警告说。  
  
这是谷歌今年第二个被谷歌积极利用的Chrome零日修补, 此前又出现了另一个高严重度的Chrome零日漏洞(CVE-2025-2783),该漏洞被滥用于针对俄罗斯政府组织、媒体机构和教育机构的网络间谍攻击。  
  
发现零日攻击的卡巴斯基研究人员表示,威胁行为者使用CVE-2025-2783漏洞绕过Google Chrome的沙箱保护,并用恶意软件感染目标。  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】FBI发布紧急警告：AI语音诈骗假冒政府高官猖獗](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069708&idx=1&sn=8a6e7a933fc907377c8b0ba2827a72b8&scene=21#wechat_redirect)  
  
  
  
[【安全圈】微软确认五月更新触发BitLocker恢复问题](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069708&idx=2&sn=ccbc2b15bbeee29c35445570f7f5c14e&scene=21#wechat_redirect)  
  
  
  
[【安全圈】科威特遭受攻击：230多个域名用于复杂的网络钓鱼行动](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069708&idx=3&sn=760b05f7cfe9bc033e4ff3aee70d0594&scene=21#wechat_redirect)  
  
  
  
[【安全圈】glibc漏洞使数百万Linux系统面临代码执行风险](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069708&idx=4&sn=21c7295802162aa16f8b54670e5a4c13&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
