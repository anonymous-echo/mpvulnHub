#  【安全圈】用友U8CRM存在SQL注入漏洞   
 安全圈   2024-10-04 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
漏洞  
  
  
**一、 漏洞描述**  
  
U8+ CRM产品存在一组非产品功能必要的残留文件，黑客通过这些文件可实现SQL注入攻击。攻击者可通过此获取服务器信息甚至获得服务器控制权  
  
  
**二、影响版本**  
  
此漏洞影响 V18, V16.5, V16.1, V16.0, V15.1, V15.0, V13版本。  
  
  
**三、修复方案**  
  
**第一步：**  
在配置文件尾部追加如下段落即可  
  
配置文件：U8SOFT\turbocrm70\apache\conf\httpd.conf，  
  
在末尾添加一个配置：  
  
<Directory "D:/U8SOFT/turbocrm70/code/www/background">  
  
Require local  
  
</Directory>  
  
其中，需要将<Directory "D:/U8SOFT/turbocrm70/code/www/background">中的u8安装路径修改为正确的安装路径  
  
  
**第二步：**  
U8CRM存在SQL注入漏洞的安全补丁240808.zip  
  
将解压文件中的U8SOFT目录覆盖产品安装目录。  
  
  
**第三步：**  
修改完之后重启Apache4TurboCRM70服务  
  
  
另：  
  
如果没有使用U8CRM模块功能，U8CRM功能仅因为产品安装时全选模块带入。需要禁用U8CRM服务。即在U8应用服务管理器中停止并禁用Apache4TurboCRM70, TurboCRM70和memcached Server。  
  
U8从v16.5开始，CRM不再作为主安装盘的一部分，而是作为独立安装盘发布。在主安装盘选择全部模块不会安装CRM模块。如果没有从单独的安装盘安装U8CRM，不会受到本漏洞影响，无需进行任何处理。  
  
  
  
   END    
  
  
阅读推荐  
  
  
[【安全圈】Cloudflare遭受3.8Tbps DDos攻击，攻击源竟是...](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652064888&idx=1&sn=22a0e79377ff8248b57da157615c571a&chksm=f36e6038c419e92efb17e5e82271a7ba31a3a3db9f7428ee79103869ba1d2f947bb57c8d752f&scene=21#wechat_redirect)  
  
  
  
[【安全圈】远程利用漏洞起亚汽车视频，（目前官方已修复漏洞）](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652064888&idx=2&sn=1de3b1f19c6574d455747d1b16ace81e&chksm=f36e6038c419e92e4019e3dfb30072db7bd47a552a5edad8d58f54d310c163ba8ce7f84d22b7&scene=21#wechat_redirect)  
  
  
  
[【安全圈】索尼PS5和微软Xbox网络双双崩溃中断影响全球玩家](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652064888&idx=3&sn=2220ddda4dcbeb5dd0424019f33b9f16&chksm=f36e6038c419e92e9557f22ddab45ad50e35c1fb7a3391b54ffffe021fef23f0d81859971f01&scene=21#wechat_redirect)  
  
  
  
[【安全圈】英国揭露LockBit勒索软件背后是俄罗斯支持的黑客](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652064888&idx=4&sn=2020e1f1c4fb89c3ed238075f1bd26c9&chksm=f36e6038c419e92ed7c6426f1bb0f37647a02b23d904e5192eaf032d2fa676f21d48c18f3c6e&scene=21#wechat_redirect)  
  
  
  
[【安全圈】ChatGPT 曝严重漏洞，聊天记录黑客随意看，网友：本地运行也没用](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652064829&idx=1&sn=43b9a1718f1914415bedb5011a00c419&chksm=f36e607dc419e96b4ba394e9fc13291a3ce749e64ec089c4e28d1af785ebaa4f48ae085b254c&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
  
  
