#  影响上千万网站，WordPress插件曝高危漏洞   
 网络安全应急技术国家工程中心   2023-04-06 14:47  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176l9eb6BrrKvcwdBwtNrsYemmFynxY6oII0AH4pvwd0j8GoCusPQN6pzEmRL3ZHC97w7eUePUKVNcw/640?wx_fmt=jpeg "")  
  
黑客正在积极利用流行的Elementor Pro WordPress插件中的高危漏洞，该插件已被超过1200万个网站使用。  
  
Elementor Pro是一款WordPress页面构建器插件，允许用户轻松构建专业外观的网站而无需了解编码知识，具有拖放、主题构建、模板集合、自定义小部件支持以及面向在线商店的WooCommerce构建器等功能。  
  
这个漏洞是由NinTechNet研究员Jerome Bruandet于2023年3月18日发现的，并在本周分享了关于如何利用与WooCommerce一起安装时可以利用此漏洞的技术细节。  
  
该漏洞影响v3.11.6及其之前的所有版本，允许像商店客户或网站成员这样的经过身份验证的用户更改网站设置甚至完全接管网站。  
  
经过身份验证的攻击者可以利用此漏洞创建管理员帐户，方法是启用注册并将默认角色设置为’管理员’、更改管理员电子邮件地址或通过更改siteurl将所有流量重定向到外部恶意网站等多种可能性。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39fPb37MBCNLtRnnG6kWHmLpBgfziaj6sjibZgNEcu4K7VVtp9TicwXwZI5AvsLzNHdmrrCQuW8cLSvQ/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
需要注意的是，要利用这个特定漏洞，网站上还必须安装WooCommerce插件，才能激活Elementor Pro上相应的易受攻击模块。Elementor插件漏洞正在被积极利用 WordPress安全公司PatchStack现在报告称黑客正在积极利用这个Elementor Pro插件漏洞将访问者重定向到恶意域名（”away[.]trackersline[.]com”）或上传后门到被攻击的网站中。  
  
此后门将允许攻击者完全访问WordPress网站，无论是窃取数据还是安装其他恶意代码。PatchStack表示，大多数针对易受攻击的网站的攻击来自以下三个IP地址，建议将它们添加到阻止列表中：193.169.194.63、193.169.195.64和194.135.30.6。  
  
如果您的网站使用Elementor Pro，则必须尽快升级到3.11.7或更高版本（最新版本为3.12），因为黑客已经开始针对易受攻击的网站进行攻击。  
  
**参考链接：**  
  
thehackernews.com/2023/04/hackers-exploiting-wordpress-elementor.html  
  
  
  
原文来源：FreeBuf  
  
“投稿联系方式：孙中豪 010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176n1NvL0JsVSB8lNDX2FCGZjW0HGfDVnFao65ic4fx6Rv4qylYEAbia4AU3V2Zz801UlicBcLeZ6gS6tg/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
