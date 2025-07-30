#  【安全圈】LiteSpeed 曝出严重漏洞，致使超 600 万 WordPress 网站遭攻击   
 安全圈   2024-09-06 19:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaz0aAPfSKT3CQcTKrPtCxqldiaHOapkXapQJn5JTVy1zhXrv184q4sT1S0vy2tySkVupibHHVcEcXg/640?wx_fmt=jpeg&from=appmsg "")  
  
近日，Patchstack 的 Rafie Muhammad 在 LiteSpeed Cache 插件中发现了一个严重漏洞，该插件主要用于加快超 600 万个 WordPress 网站的用户浏览速度。该漏洞被追踪为 CVE-2024-44000，并被归类为未经身份验证的帐户接管问题 。随着 LiteSpeed Cache 6.5.0.1 版本的发布，修复程序也于昨天（9月4日）发布。  
## 调试功能将 cookie 写入文件  
  
该漏洞与插件的调试日志功能有关，当启用该功能时，它会将所有 HTTP 响应头（包括 “Set-Cookie ”头）记录到文件中。  
  
这些标头包含用于验证用户身份的会话 cookie，一旦攻击者成功窃取这些 cookie，就可以冒充管理员用户完全控制网站。  
  
要利用该漏洞，攻击者必须能够访问“/wp-content/debug.log ”中的调试日志文件。在未实施文件访问限制（如 .htaccess 规则）的情况下，只需输入正确的 URL 即可。  
  
当然，攻击者只能窃取在调试功能激活时登录网站的用户的会话 cookie，但如果日志被无限期保存而不是定期清除，这甚至包括过去的登录事件。  
  
该插件的供应商 LiteSpeed Technologies 通过将调试日志移至专用文件夹（'/wp-content/litespeed/debug/'）、随机化日志文件名、移除记录 Cookie 的选项，以及添加一个虚假索引文件以提供额外保护，解决了这一问题。  
  
建议 LiteSpeed Cache 用户清除其服务器上的所有 “debug.log ”文件，以删除可能被威胁行为者窃取的潜在有效会话 cookie。  
  
此外，还应设置 .htaccess 规则，拒绝直接访问日志文件，因为新系统上的随机名称仍可能通过暴力破解来猜测。  
  
WordPress.org报告称，昨天，也就是v6.5.0.1发布的当天，下载LiteSpeed Cache的用户刚刚超过37.5万，因此易受这些攻击影响的网站数量可能超过560万。  
## 受到攻击的 LiteSpeed Cache  
  
LiteSpeed Cache 插件漏洞因其广泛的影响力成为了近期安全研究人员的重点研究对象。与此同时，黑客们一直在寻找机会通过利用该漏洞对网站发起攻击。  
  
2024 年 5 月，有人发现黑客利用该插件的一个过时版本（受跟踪为 CVE-2023-40000 的未验证跨站脚本缺陷影响）创建管理员用户并控制网站。  
  
今年 8 月 21 日，研究人员又发现了一个关键的未经身份验证的权限升级漏洞，该漏洞被追踪为 CVE-2024-28000，研究人员对利用该漏洞的难度敲响了警钟。  
  
该漏洞披露后仅几个小时，威胁者就开始大规模攻击网站，Wordfence 报告称阻止了近 5万次攻击。  
  
据统计，在过去的 24 小时内，因其漏洞导致的攻击次数达到了 34 万次。  
  
参考来源：  
LiteSpeed Cache bug exposes 6 million WordPress sites to takeover attacks   
  
  
END  
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaz0aAPfSKT3CQcTKrPtCxqm3Zn20xgFneKIB4EPHFIQ8Mh0aHlUddAnicDpzRsjGo36CrR8LLbJfQ/640?wx_fmt=jpeg "")  
[【安全圈】微软开源的PowerToys将增加新功能：可以在Win11右键中增加自定义菜单](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652064155&idx=1&sn=9768c552501bc5e793502b3ffb847c14&chksm=f36e65dbc419eccde127c105e5df547489ec0367fe40c216a29028b6fda7577cf36a8385dc53&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaz0aAPfSKT3CQcTKrPtCxqxCiafg1JjEstXZ2OxCmx6GV7ah2NPIDicn10zuY4yEt96qE4bALicyeQQ/640?wx_fmt=jpeg "")  
[【安全圈】黑客活动家利用 WinRAR 漏洞对俄罗斯和白俄罗斯发动攻击](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652064155&idx=2&sn=de3e082d1b464df6bafb89d960eb9d2e&chksm=f36e65dbc419eccdc65c3c9886708563d4798ca4373e54e9333b5c96241fc735474ab3c62cce&scene=21#wechat_redirect)  
  
  
【安全圈】网络身份证是强制，会影响正常上网？公安部详细回应  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaz0aAPfSKT3CQcTKrPtCxqnKE0hicjwia0QMyNjE5ibhjyOwnQ6sSgy5Ir1TSZtV15tpGWpEaBYGEmw/640?wx_fmt=jpeg "")  
[【安全圈】红队工具MacroPack已被攻击者滥用](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652064155&idx=3&sn=1c92121ff9d15699b98ef79a6f392b4e&chksm=f36e65dbc419eccd5c7b6d46073fdcd9423c0fd11f391d38dbaa092dea6a174280662e2896a5&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaz0aAPfSKT3CQcTKrPtCxqj1gbVxYFd1DeDficLtx5zhgQVaXopZibaISzmaET4dOEcqVx05mgJTUw/640?wx_fmt=jpeg "")  
[【安全圈】新型PyPI攻击技术可能导致超2.2万软件包被劫持](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652064155&idx=4&sn=87672b59a7facd21c15d9ef3cdaed095&chksm=f36e65dbc419eccda3412021d06a4546910f5cbb9844eca085d0f7edc5acb1683d75a5073d89&scene=21#wechat_redirect)  
             
  
  
  
  
  
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
  
