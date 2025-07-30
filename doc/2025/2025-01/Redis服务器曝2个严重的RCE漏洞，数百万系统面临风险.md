#  Redis服务器曝2个严重的RCE漏洞，数百万系统面临风险   
老布  FreeBuf   2025-01-07 10:59  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38rmg9xJmNnZ1MqNxribsANKKqZ8bSiavjUAhQzvUSTXnvX6pDIUzLw0wibzH8LyCmHWW1Z26LNVXh1Q/640?wx_fmt=jpeg&from=appmsg "")  
  
  
在广泛使用的内存数据库Redis里发现了两个严重漏洞，这可能使数百万系统面临拒绝服务（DoS）攻击和远程代码执行（RCE）的风险。这些漏洞被标记为CVE - 2024 - 51741和CVE - 2024 - 46981，这凸显了Redis用户面临着重大的安全风险，也强调了及时更新和采取缓解措施的重要性。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38rmg9xJmNnZ1MqNxribsANKqIg4KQIJzibkFutT3LMhbkVCdCzwVSdwXAT2Kh9vJb6PTozcpL9vFnw/640?wx_fmt=jpeg&from=appmsg "")  
###   
### 一、CVE - 2024 - 51741：畸形ACL选择器引发的拒绝服务  
  
  
CVE - 2024 - 51741这个漏洞影响Redis 7.0.0及以上版本。拥有足够权限的认证用户能够创建一个畸形的访问控制列表（ACL）选择器。  
  
  
当访问这个畸形选择器时，服务器就会崩溃，从而进入拒绝服务状态。该问题已在Redis 7.2.7和7.4.2版本中得到修复。  
  
  
Redis用户应马上升级到这些修复后的版本，从而保护自己的系统免受可能的利用。此漏洞是由Axel Mierczuk报告的，他为发现这个漏洞做出了贡献。  
  
### 二、CVE - 2024 - 46981：Lua脚本执行远程代码  
  
  
CVE - 2024 - 46981这个漏洞带来的威胁更大，因为它可能导致远程代码执行。这个问题是由于Redis中Lua脚本功能被滥用而产生的。认证过的攻击者能够编写恶意的Lua脚本来操纵垃圾收集器，进而可能在服务器上执行任意代码。  
  
  
这个漏洞影响所有开启了Lua脚本功能的Redis版本。针对Redis 6.2.x、7.2.x和7.4.x版本已经发布了修补程序。对于那些不能马上更新的用户，建议通过修改ACL规则来限制“EVAL”和“EVALSHA”命令，从而禁用Lua脚本作为额外的防范措施。  
  
### 三、建议措施  
  
  
**1. 升级Redis**  
  
用户应该把安装更新到已修复漏洞的版本，即针对CVE - 2024 - 51741的7.2.7或7.4.2版本，以及针对CVE - 2024 - 46981的最新版本。  
  
**2. 限制Lua脚本**  
  
作为针对CVE - 2024 - 46981的临时解决办法，通过修改ACL规则阻止“EVAL”和“EVALSHA”命令来禁用Lua脚本。  
  
**3. 监控访问控制**  
  
要确保只有受信任的用户才能在Redis服务器上执行特权命令。这些漏洞表明在管理数据库系统时实施强大安全策略是非常关键的。强烈建议Redis用户立即行动起来，减轻风险，保护自己的环境免受潜在的利用。  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊】  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ic5icaZr7IGkVcd3DT6vXW4B4LOZ1M7YkTPhS1AT2DQJaicFjtCxt5BRO7p5AOJqvH3EJABCd0BFqYQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
