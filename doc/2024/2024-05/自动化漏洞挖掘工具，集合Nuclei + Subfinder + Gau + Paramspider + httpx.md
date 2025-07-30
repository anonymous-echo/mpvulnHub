#  自动化漏洞挖掘工具，集合Nuclei + Subfinder + Gau + Paramspider + httpx   
Mr.x  黑客白帽子   2024-05-18 08:31  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJG3jJlPv0w6V8YUTyNSuV2udfyY3rWyR6V1UeHWuiab6T80I5ldZicZswCnrbicD4ibpaDMqCZ6UvFmhWLyTzptSA/640?wx_fmt=png&random=0.6636094571400317&random=0.6219011309810436&random=0.21191420540585404 "")  
  
**感谢师傅 · 关注我们**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJG3jJlPv0w6V8YUTyNSuV2udfyY3rWyR6V1UeHWuiab6T80I5ldZicZswCnrbicD4ibpaDMqCZ6UvFmhWLyTzptSA/640?wx_fmt=png&random=0.9829534454876507&random=0.2787622380037358&random=0.29583791053286834 "")  
  
  
由于，微信公众号推送机制改变，现在需要设置为星标才能收到推送消息。大家就动动发财小手设置一下呗！啾咪~~~  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJG3jJlPv0y50hQk1TiaBIAnSjzqkmZcPS4TWvohHfHPTVUBWM2mFxcqwhiaZKaQM6S7t11fuiajZ2zZqXD5hJJmA/640?wx_fmt=png "")  
  
  
## 🌟简介  
  
NucleiScanner是一个强大的自动化工具，用于检测Web应用程序中的未知漏洞。  
  
NucleiScanner  
是一个自动化工具，它结合了Nuclei  
、Subfinder  
、Gau  
、Paramspider  
和httpx  
功能，以增强Web应用程序安全测试。它使用Subfinder  
来收集子域，Gau  
通过过滤不需要的扩展来收集URL，ParamSpider  
用于识别潜在的入口点，Nuclei Scanning templates  
用于  
扫描漏洞  
。NucleiScanner  
简化了流程，使安全专业人员和Web开发人员更容易有效地检测和解决安全风险。下载NucleiScanner  
以保护您的Web应用程序免受漏洞和攻击。  
  
注：Nuclei+Subfinder+Gau+Paramspider+httpx=NucleiScanner重要提示：请确保工具Nuclei、Subfinder、Gau、Paramspider、httpx已安装在您的机器上，并正确执行，以使用NucleiScanner而不会出现任何问题。&  
### 工具包括：  
  
  
```
Nucleigit clone https://github.com/projectdiscovery/nuclei.git

Subfindergit clone https://github.com/projectdiscovery/subfinder.git

Gaugit clone https://github.com/lc/gau.git

ParamSpider git clone https://github.com/0xKayala/ParamSpider.git

httpxgit clone https://github.com/projectdiscovery/httpx.git
```  
  
  
### 模板：Nuclei模板git clone https://github.com/projectdiscovery/nuclei-templates.git  
## 截图  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PJG3jJlPv0yE1DqXrgicZOLiajr3wU77zxvhrB86Kzb63iav0250moPazMicJZKau6kXFQh2aicMk1NtP59t5XrpJqQ/640?wx_fmt=png&from=appmsg "")  
  
使用  
  
```
ns -h
```  
  
  
这将显示该工具的帮助。以下是它支持的选项。  
```
NucleiScanner is a Powerful Automation tool for detecting Unknown Vulnerabilities in Web Applications

Usage: /usr/bin/ns [options]

Options:
  -h, --help              Display help information
  -d, --domain <domain>   Domain to scan for Unknown Vulnerabilities
  -f, --file <filename>   File containing multiple domains/URLs to scan
```  
  
## 安装：要安装NucleiScanner，请执行以下步骤：  
```
git clone https://github.com/0xKayala/NucleiScanner.git && cd NucleiScanner && sudo chmod +x install.sh && ./install.sh && ns -h && cd ..

```  
  
## 示例：以下是如何使用NucleiScanner的一些示例：  
- 在单个域上运行NucleiScanner：  
```
```  
  
  
- 从一个文件在多个域上运行NucleiScanner：  
```
```  
  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650939865&idx=1&sn=773462fd879df4c210ad316ed538483a&chksm=8bac6d26bcdbe4302b3b28dac2f62deaa16dc687bff0062a8ca5d90f6b124e3d2685544fdc03&scene=21#wechat_redirect)  
  
**下载地址**  
  
**点击下方名片进入公众号**  
  
**回复关键字【**  
**0518****】获取网盘**  
**下载链接**  
  
**二个月前资源汇总**  
  
https://kdocs.cn/l/cq  
EYzWfs0kUS  
  
  
  

								  

									  

										  

											  
往期推荐  

										  

									  

									  

								[ Commando VM 3.0 红队渗透工具集 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650950760&idx=1&sn=e1d39ddf41f423aba8a12302822ec744&chksm=8bac0097bcdb8981784433c2413c95286683cbb498fd138ebe5bb439bf7b213e320d050b432a&scene=21#wechat_redirect)  

							  
  

								[ 工具更新 | 最强渗透集成环境 V 5.0 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650950673&idx=1&sn=32411457c72a555d2ac824777e0d6fc8&chksm=8bac00eebcdb89f857f90279fd1e64de07dbec32044116780602c4f749a8d6fa9f67567cd984&scene=21#wechat_redirect)  

							  
  

								[ 实战 | 渗透中优雅地寻找网站源码 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650950566&idx=1&sn=dbb56490dbc49f28f1113a26dcfd613f&chksm=8bac0759bcdb8e4f01e5b64ea1448918473489168dd97a8d968e0a27c818ce1884f9541473cd&scene=21#wechat_redirect)  

							  
  

								[ 一款后渗透免杀工具，助力每一位像我这样的脚本小子快速实现免杀，支持bypass 360 火绒 Windows Defender ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650950484&idx=1&sn=d23e6a8c0a99420cc83d4d9813d48be8&chksm=8bac07abbcdb8ebd8013f21b735f57c1ffdabd5e9304448004ab7d42b9bb7c502614ee77497e&scene=21#wechat_redirect)  

							  
  

								[ 记一次HW供应链攻击到SQL注入新用法 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650950401&idx=1&sn=c2086208b7cedbc2e91d62615ade54ab&chksm=8bac07febcdb8ee8a6eb75b0366b339e130623c757d6bd5ae9b0822ae72ec95af6c371d585b9&scene=21#wechat_redirect)  

							  
  

								[ 记一次梦游渗透从jmx到rce ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650950304&idx=1&sn=555ca3dfd42505a6d2f83bc1b19d3c11&chksm=8bac065fbcdb8f498e7dfd414e9d26cf4bd35be962e8550299b84d16430742b3356bef7f6e3f&scene=21#wechat_redirect)  

							  
  

								[ 记某积分商城任意金额支付漏洞分析利用及思考 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650950208&idx=1&sn=41596a2087dd835e41026c6a1f7f6c76&chksm=8bac06bfbcdb8fa939c39f8d0ac6aa2d7c5ba2d25fafb0777a4376bc98f964347ec17e858279&scene=21#wechat_redirect)  

							  
  

								[ 记一次安服薅洞实战 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650950122&idx=1&sn=ecfced4a60775a1ee7d681ca868c82ba&chksm=8bac0515bcdb8c03f0e0020fe6e0d590df5c7bfcc55243d562edfbd8253268e41bcf1659d9c6&scene=21#wechat_redirect)  

							  
  

								[ GitHub开源攻防武器合集 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650950031&idx=1&sn=58f179341961e07931c8d501c7af51a0&chksm=8bac0570bcdb8c66c1d0870abd37ff4bf741a6e4e37b505ce3868e51733e628cfd8abb6dd0fe&scene=21#wechat_redirect)  

							  
  

								[ JScanner一款隐藏Url接口探测/目录递归访问请求工具|漏洞探测 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650949969&idx=1&sn=8ac663be927a8e2c8ef07aa1269724c8&chksm=8bac05aebcdb8cb862b879cc660129c8531115196e09e50da20edbcf54729d9dc3ebf380574c&scene=21#wechat_redirect)  

							  
  
  
  
声明：本公众号所分享内容仅用于网安爱好者之间的技术讨论，禁止用于违法途径，**所有渗透都需获取授权**  
！否则需自行承担，本公众号及原作者不承担相应的后果  
```
```  
  
  
