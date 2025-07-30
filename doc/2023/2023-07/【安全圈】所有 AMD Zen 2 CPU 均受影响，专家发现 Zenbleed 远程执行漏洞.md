#  【安全圈】所有 AMD Zen 2 CPU 均受影响，专家发现 Zenbleed 远程执行漏洞   
 安全圈   2023-07-26 10:59  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylgSxa9I02IBd3bgLEhwfJCeRibw3LEjMujeAhD2CvyiaVCZJVHGHODbkPx3pViaX0sAibZsDun6sicUzdQ/640?wx_fmt=jpeg "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
7 月 25 日消息，谷歌信息安全研究员 Tavis Ormandy 今天发布博文，表示基于 Zen 2 的 AMD 处理器中发现了新的安全漏洞，**并将其命名为 Zenbleed。**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgVfeJwnTvMUE6CnG728Z4QTfR28Sv5aB4BC3kkQ2KKvHYLaVkV0lu3PAKRh6gx3sDrqeEWryb1FQ/640?wx_fmt=jpeg "")  
  
Ormandy 表示所有基于 Zen 2 的 AMD 处理器均受到影响，黑客可以利用该漏洞，窃取加密密钥和用户登录凭证等受到保护的信息。  
  
  
Ormandy 表示黑客不需要物理访问计算机，可以通过网页上的恶意 JS 脚本执行。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgVfeJwnTvMUE6CnG728Z4QmFlz32HlxBdaP2OQVTS1WL34K2fO4uGQxu2RgOCGv5mvEEVGcrXupA/640?wx_fmt=jpeg "")  
  
Ormandy 于 2023 年 5 月 15 日向 AMD 报告了该问题，**AMD 官方已经发布了有针对性的补丁**  
，Ormandy 并未确认新版固件是否已完全修复该漏洞。  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgVfeJwnTvMUE6CnG728Z4QT8YeIckz6WRBAXD8IZemuLznibdN3A3YaCD4TY50a9b2Y8cK8a2KDWA/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgVfeJwnTvMUE6CnG728Z4QrPJLkl6InNB8n2Mb0DtHytlnsaQ2xZn34YlLyaQBzdrZHQxzGcYTNQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgVfeJwnTvMUE6CnG728Z4QrqKNuW1Qs3Cp6RKWdxYDxYPN4P9P2u0LkXnW4jHAj3cDPfaoiaydr3g/640?wx_fmt=jpeg "")  
  
该漏洞追踪编号为 CVE-2023-20593，**能以每核心每秒 30KB 的速度窃取机密数据。**  
此攻击会影响 CPU 上运行的所有软件，包括虚拟机、沙箱、容器和进程。  
  
  
IT 之家在此附上受影响的 Zen 2 处理器清单：  
  
AMD Ryzen 3000 系列处理器；  
  
AMD Ryzen PRO 3000 系列处理器；  
  
AMD Ryzen Threadripper 3000 系列处理器；  
  
带 Radeon 集显的 AMD Ryzen 4000 系列处理器；  
  
AMD Ryzen PRO 4000 系列处理器；  
  
带 Radeon 集显的 AMD Ryzen 5000 系列处理器；  
  
带 Radeon 集显的 AMD Ryzen 7020 系列处理器；  
  
AMD EPYC Rome 系列处理器。  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgVfeJwnTvMUE6CnG728Z4QuIWyOk7beXxVibsgLFHdjPcq6BqT8zRRoEGPXU4WnwVHibiaXy9y8yHBg/640?wx_fmt=png "")  
[【安全圈】遭遇攻击，铃木两家授权经销商网站泄露客户的数据信息！](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652040284&idx=1&sn=7232f633b80fd250c75ceb789d545f37&chksm=f36fc01cc418490afbc96ea2f8929a9974ecabd98ec9c5bf0ffa23af85ee3ca540abf91e1636&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgVfeJwnTvMUE6CnG728Z4Qf2BH0Yn7VUj2yccKPolOsGWo17oodLlW0VlhciaNNA95k6kss1s8jRg/640?wx_fmt=png "")  
[【安全圈】近4000个开发者账户信息被盗，Roblox数据泄露影响范围较广](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652040284&idx=2&sn=7093617731c4dec5acde2e048be148fb&chksm=f36fc01cc418490ac7ac3ab0afdb6d06eebaecb5c98d43b7cf35981ea19b603957cfac96e977&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgVfeJwnTvMUE6CnG728Z4QRkHvjsDgEMgxsvcS7mPApGBbyRlicHUGiaB2IFuWpGGAicuXXyia5szAaw/640?wx_fmt=png "")  
[【安全圈】2023年数据泄密平均成本达445万美元，创下IBM报告历史新高！](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652040284&idx=3&sn=e73413ce0debef4915aa14ce53aebe2a&chksm=f36fc01cc418490aac7cd878b52f9d8850cb27d9f4af8eea8866b72e9019776845451ec67a05&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljgVu75Xcz1wdjmJb3OnNuic1ADUGgVwxTib9XOlYsr8GmMaiaUzm0cZFG3LibiazibqLUhoia6r679eVI9g/640?wx_fmt=png "")  
[【安全圈】苹果发布安全更新，修复今年第 11 个零日漏洞！](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652040284&idx=4&sn=1f5542946173171888a9fe0f6c9f2838&chksm=f36fc01cc418490aa932cb9a17255d195171d3e9a2634873a77502b5eb2f7088d4a4c11c4c51&scene=21#wechat_redirect)  
  
  
  
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
  
  
