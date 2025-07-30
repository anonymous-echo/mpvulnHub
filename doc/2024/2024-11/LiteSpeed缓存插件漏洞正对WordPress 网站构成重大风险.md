#  LiteSpeed缓存插件漏洞正对WordPress 网站构成重大风险   
FreeBuf  商密君   2024-11-03 18:41  
  
WordPress 一款流行插件LiteSpeed Cache 的免费版本最近修复了一个高危的权限提升缺陷，该漏洞可能允许未经身份验证的网站访问者获得管理员权限。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibcCcMIKibEQpoQU4tXhjhg3ufOcQbHkg60XFocBZGJOqiapj91JDyUtqTlZmmGWiaB28ibPYoLoNRGSQ/640?wx_fmt=jpeg&from=appmsg&wxfrom=13&tp=wxpic "")  
  
  
LiteSpeed Cache 是一个缓存插件，被超过 600 万个 WordPress 网站使用，有助于加速和改善用户浏览体验。  
  
  
新发现的被跟踪为 CVE-2024-50550 的高严重性漏洞是由插件的“角色模拟”功能中的弱哈希检查引起的，该功能旨在模拟用户角色，以帮助爬虫从不同的用户级别进行站点扫描。  
  
  
该功能的函数 （'is_role_simulation（）'） 使用存储在 cookie 中的弱安全哈希值（'litespeed_hash' 和 'litespeed_flash_hash'）执行两个主要检查。但是，这些哈希值的生成具有有限的随机性，因此在某些配置下是可预测的。  
  
  
要使 CVE-2024-50550 可被利用，需要在爬网程序中配置以下设置：  
  
1. 运行持续时间和间隔设置在 2500 到 4000 秒之间。  
  
1. 服务器负载限制设置为 0。  
  
1. 角色模拟设置为 administrator。  
  
Patchstack 的安全研究员称，尽管哈希值有 32 个字符长度，但攻击者可以在 100 万种可能性的集合中进行暴力破解。  
  
  
成功利用此漏洞的攻击者可以模拟管理员角色，这意味着他们可以上传和安装任意插件或恶意软件、访问后端数据库、编辑网页等。  
  
  
10 月 17 日，供应商 LiteSpeed Technologies 在插件的 6.5.2 版本中发布了针对 CVE-2024-50550 的修复程序，提高了哈希值的随机性，并使暴力破解变得几乎无效。但根据 WordPress.org 下载统计数据，自补丁发布以来，大约有 200 万个网站进行了升级，仍有 400 万个网站暴露在漏洞中。  
  
  
**LiteSpeed 的安全难题**  
  
  
  
今年对于 LiteSpeed Cache 及其用户来说是多事之秋，因为这个流行的插件出现了多个关键漏洞，其中一些漏洞被用到了实际的攻击事件中。  
  
  
2024 年 5 月，黑客利用具有未经身份验证的跨站点脚本缺陷 （CVE-2023-40000） 的过时版本的插件创建管理员帐户并接管站点。  
  
  
2024年 8 月，研究人员发现了一个关键的未经身份验证的权限提升漏洞 （CVE-2024-28000），警告其很容易被利用。在披露后的几个小时内，攻击者就发起了大规模攻击，Wordfence阻止的恶意尝试次数达到了5万次。  
  
  
2024年9月，该插件还修复了一个漏洞（CVE-2024-44000），该漏洞能导致未经身份验证的帐户接管。  
  
  
编辑：陈十九  
  
审核：商密君  
  
**征文启事**  
  
大家好，为了更好地促进同业间学术交流，商密君现开启征文活动，只要你对商用密码、网络安全、数据加密等有自己的独到见解和想法，都可以积极向商密君投稿，商密君一定将您的声音传递给更多的人。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1HyKzSU2XXNcXmbiaiaCljdXpwzOEQ9QTBXMibM6rZTOnbTSwTmCXncQLria2vuLGxn8QPtznzBc0as8vBxWIjrWxQ/640?wx_fmt=jpeg "")  
  
来源：FreeBuf  
  
注：内容均来源于互联网，版权归作者所有，如有侵权，请联系告知，我们将尽快处理。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1HyKzSU2XXOdeQx0thlyozF2swQTEN9iaaBNDG0jTKfAgqgdesve8x5IEWNvYxjF6sAWjO1TPCZVsWd0oiaDn3uw/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1HyKzSU2XXMyyClGk1cttkSBbJicAn5drpXEbFIeChG9IkrslYEylRF4Z6KNaxNafDwr5ibcYaZXdnveQCNIr5kw/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1HyKzSU2XXMZPiaDBD8yxbIHiciauWK4tuiaMcJkA69QYZ9T4jmc3fdN6EA7Qq9A8E3RWcTKhxVEU1QjqOgrJMu2Qg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
点分享  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1HyKzSU2XXMZPiaDBD8yxbIHiciauWK4tuiaiaRXdw4BFsc7MxzkVZaKGgtjWA5GKtUfm3hlgzsBtjJ0mnh9QibeFOGQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
点点赞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1HyKzSU2XXMZPiaDBD8yxbIHiciauWK4tuiaeiaNlRO9954g4VS87icD7KQdxzokTGDIjmCJA563IwfStoFzPUaliauXg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
点在看  
  
