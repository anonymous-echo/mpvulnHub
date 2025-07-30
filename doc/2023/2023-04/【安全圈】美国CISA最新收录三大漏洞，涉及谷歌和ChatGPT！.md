#  【安全圈】美国CISA最新收录三大漏洞，涉及谷歌和ChatGPT！   
 安全圈   2023-04-23 20:00  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGyljsJVJHhaCOeUkoze16FrNjE24yjZVib01Tl7diaq0PGm6wazJMuo3K51rsrhdiagwEDicqXQtmMQlIJQ/640?wx_fmt=jpeg "")  
  
**关键词**  
  
  
  
勒索软件  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGyljviaibVr7hheUqyCoKWvqWVGkxUmqcwicuYPYWINWeEI2I5szJdAR17ic6Sl5cObB4Vy4RYiaOoZa8pXw/640?wx_fmt=jpeg "")  
  
上周五，美国网络安全和基础设施安全局(CISA)在其漏洞(KEV)目录中新增三个安全漏洞，具体如下：  
  
CVE-2023-28432 (CVSS评分- 7.5)- MinIO信息泄露漏洞  
  
CVE-2023-27350 (CVSS评分- 9.8)-剪纸MF/NG不当访问控制漏洞  
  
CVE-2023-2136 (CVSS评分-待定)-谷歌Chrome Skia整数溢出漏洞  
  
MinIO的维护人员在2023年3月21日发布的一份资讯报告中表示，在集群部署中，MINIO_SECRET_KEY和MINIO_ROOT_PASSWORD会还原所有环境变量，导致信息泄露。  
  
据GreyNoise收集的数据显示，在过去的30天里，来自美国、荷兰、法国、日本和芬兰等多达18个恶意IP地址试图利用该漏洞。值得注意的是，这家威胁情报公司在上月底发布的警报文件中指出，OpenAI为开发者提供了一个参考方法，阐述了如何将他们的插件集成到ChatGPT上，主要是依赖于一个旧版本的MinIO，而该版本存在CVE-2023-28432的漏洞。  
  
GreyNoise表示，OpenAI开发的新功能对于那些想在ChatGPT集成中访问不同提供商实时数据的开发人员来说，的确是一个非常有价值的工具，但安全性始终应该是摆在首位的核心设计原则。  
  
此外，KEV目录中还添加了一个会致使PaperCut软件远程代码执行错误的漏洞。攻击者可以通过该漏洞实现免身份验证，并直接远程运行任意代码。  
  
不过截至2023年3月8日，供应商已经修复了该漏洞，并发布了PaperCut MF和PaperCut NG20.1.7,21.2.11和22.0.9版本。Zero Day Initiative已于2023年1月10日正式报告了该问题，并预计将于2023年5月10日发布更多技术细节。  
  
本周早些时候，有一家总部位于墨尔本的公司分享了一则最新消息称：有证据表明，在2023年4月18日左右，有攻击者通过漏洞攻击了未打补丁服务器。网络安全公司北极狼(Arctic Wolf)表示，此前也发现了一些PaperCut服务器被入侵的情况。一经入侵，RMM的工具Synchro MSP会直接在被损害系统上自动加载。  
  
最后一个被添加至目录的是谷歌Chrome漏洞，该漏洞会直接影响到Skia 2D图形库，并可以让威胁者通过精心制作的HTML页面执行沙盒逃逸。  
  
CISA建议美国联邦民事行政部门(FCEB)机构在2023年5月12日之前尽快修复这几个漏洞，以确保其网络安全。  
  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylhnp7R98NzxRzRb27nOanbOeqibmSbx1ZG58XV67PtUxJjshibSY7icZtn3omuRk7PafycAjPogrHs6g/640?wx_fmt=jpeg "")  
[【安全圈】现已修复！阿里云SQL 数据库曝两个关键漏洞](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652032821&idx=1&sn=1c4a278828b2ff1092ac903cd3b4a436&chksm=f36fe375c4186a630be4ae42843ca86ebd932da52439bc4b47724ffa365daeee9a3d233b1b1e&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGyljTubIXdbemJ554QB3reRAqab0DQecx5e5ib7Bjmg8Z5GQEClJ57DBTgbRjicJ4QSYiaNaPtnSBhfzyQ/640?wx_fmt=jpeg "")  
[【安全圈】全国首例：长沙一男子植入“戒酒芯片”，管用 5 个月](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652032676&idx=1&sn=9a4b287138977c589ba952ff0efb2904&chksm=f36fe2e4c4186bf20204e3cf731bb312cf995dd78926c152b47288323ba1b46ada3ef8adaf2f&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGyljR5lKraSf9jwLZCNgibbBD3HmUweiajPbOXsAPHZibX7mPT4lwFAURzYc25JvzLl2faLAJH5ltDLgZg/640?wx_fmt=png "")  
[](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652032584&idx=1&sn=eb70ec73c5ec975d3380dd1b4354629a&chksm=f36fe208c4186b1e7a6d8eec303a68844444d99cc409dec88ba69cb080d0717150b35bfde912&scene=21#wechat_redirect)  
[【安全圈】击穿24款杀毒软件，Money Message勒索病毒肆虐全网](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652030409&idx=3&sn=f0ed1e90be21ec20acf4e292d370dc2a&chksm=f36fe989c418609f395b2d771f88413c9213561a925c09bfd92a44f0909f40be3f571b86f878&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylia0fH2qvzBGgJFjCAiaxicR7BMLPC5NbISyic99moCdnib521cGoTFCVQ42WrOCCMWDXvGnZpHB9Db7AA/640?wx_fmt=png "")  
[【安全圈】人美声甜 GPT，数学题哪里不会讲哪里](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652030409&idx=2&sn=90e658f20ef737f7b5e5b01ed5ec65a2&chksm=f36fe989c418609f55a385596c83266489845317fa6e009ecf007bc50164f6a802403fdc403c&scene=21#wechat_redirect)  
  
  
  
[【安全](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652030093&idx=4&sn=e988dc890e595695befbdb177d11b98c&chksm=f36fe8cdc41861dbd78f5270a42fca19c1d45cb375ef4469e8a36bef1f42620f990d03714872&scene=21#wechat_redirect)  
  
  
‍  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
  
