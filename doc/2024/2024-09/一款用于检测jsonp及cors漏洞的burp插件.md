#  一款用于检测jsonp及cors漏洞的burp插件   
yuebusao  夜组安全   2024-09-21 10:30  
  
免责声明  
  
由于传播、利用本公众号夜组安全所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号夜组安全及作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
**所有工具安全性自测！！！VX：**  
**baobeiaini_ya**  
  
朋友们现在只对常读和星标的公众号才展示大图推送，建议大家把  
**夜组安全**  
“**设为星标**  
”，  
否则可能就看不到了啦！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2Xvvlzc5lra8XdgLYGCfX5ooaMiaUJy4vKvStTngQp4122jauXltltcCuYib5WBBdaXu5dh91dGvibyQ/640?wx_fmt=png&from=appmsg "")  
  
  
**01**  
  
**工具介绍**  
  
一款被动扫描检测  
jsonp  
及  
cors  
漏洞的  
burpsuite  
插件，魔改自  
https://github.com/YoDiDi/cors-jsonp  
。优化了  
JSONP  
及  
CORS  
的检测逻辑，在原有基础上降低了  
jsonp  
漏洞检测误报。  
  
**02**  
  
**工具功能**  
  
- 低误报检测JSONP漏洞，检测有无Referer头校验，可选择是否只检测存在泄漏敏感信息字段的JSONP接口。  
  
- 内置了JSONP特征检测及敏感信息抽取正则表达式，使用者可灵活修改参数。  
  
- 零误报检测CORS配置漏洞。  
  
  
  
**03**  
  
**检测思路**  
  
1. 根据关键字修改http包，重新发包1。  
  
1. 检测是否存在JSONP，如果满足以下条件则认为存在JSONP：  
  
1. Callee.Name 与 callback函数名相同  
  
1. 返回包满足JSONP回显包的特征  
  
1. 修改Referer头检测重新发包2，通过计算发包1及发包2内容的LevenshteinDistance相似度来判断该JSONP漏洞是否可利用。  
  
  
  
**04**  
  
**工具使用**  
  
编译jsonp-cors-killer项目，将jsonp-cors-killer.jar导入burp，检测到的漏洞会输出到图形界面中。  
  
  
如果提取到敏感信息字段，则会在issue中看到抽取出来的敏感字段（见下图包1、2）；若检测到是JSONP接口但未发现敏感信息字段，在打开onlySensitiveJSONP检测的情况下也会将payload显示在界面中。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2VLDOzWIicnGHibeP8HsKg8m8b4JCvE1uEEfDlwUib5cVCm8FUsN95SEpX1OibJgXyhY6CAD7tq30FsyA/640?wx_fmt=png&from=appmsg "")  
  
jsonp key words为jsonp接口常见的query key，可自行添加。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2VLDOzWIicnGHibeP8HsKg8m8eNXbgZ284OMUFp9iaPJDehficicYLMlmoA29oFWr7micINLic4nibYsUaZIQ/640?wx_fmt=png&from=appmsg "")  
  
config为JSONP检测算法的参数  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2VLDOzWIicnGHibeP8HsKg8m8fhDnkQx2vV3q5gTjliaEwenGjriclibvKcbOcpIO6zArh5PoibyRt6Xlww/640?wx_fmt=png&from=appmsg "")  
1. threshold：计算两个response body的相似度，用于检测是否有Referer头防护。经分析发现，JSONP可能会带有时间戳等信息，即便没有Referer头检测，两个回显包也可能不一致，因此用equals来判断两次发包得到的内容会带来误报，这里使用LevenshteinDistance算法计算两个文本相似度来降低误报。  
  
1. jsonpRegex：jsonp模式的正则匹配表达式，一般不用修改。  
  
1. sensitiveInfoRegex：抽取敏感信息正则表达式。  
  
1. onlySensitiveJSONP：是否显示存在敏感信息泄漏的JSONP接口，若不过滤则修改为false。  
  
1. cors：是否检测cors漏洞，若检测修改为true。  
  
  
  
**05**  
  
**工具下载**  
  
**点击关注下方名片****进入公众号**  
  
**回复关键字【240921****】获取**  
**下载链接**  
  
  
**06**  
  
**往期精彩**  

							  
[ 网络空间测绘、子域名枚举、端口扫描、敏感信息发现、漏洞扫描、分布式节点 ](http://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247492255&idx=1&sn=995b066bcb820fb28f983833331d725d&chksm=c36ba667f41c2f7164310257a240471d98459e0e7759c6168d36dbc86d2d1ce7caec6e30a784&scene=21#wechat_redirect)  

						  
  

							  
[ Exchange 信息收集工具 ](http://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247492221&idx=1&sn=482263ab19cae82ce93edc2f648803ae&chksm=c36ba685f41c2f935aefd27aaa55f09203761f8dc1b7df2a1182d6b8981f722878aa45038485&scene=21#wechat_redirect)  

						  
  

							  
[ 一款高效的 Socks5 代理采集与使用工具 ](http://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247492200&idx=1&sn=f472e178039ef296baf8a8571079fe67&chksm=c36ba690f41c2f867567cb3b5bc6c002c023a90c7e9df92eea8fa779f595d2f6ab6f0ef26fbb&scene=21#wechat_redirect)  

						  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAmMqjhMehrtxRQaYnbrvafmXHe0AwWLr2mdZxcg9wia7gVTfBbpfT6kR2xkjzsZ6bTTu5YCbytuoshPcddfsNg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&random=0.8399406679299557 "")  
  
  
