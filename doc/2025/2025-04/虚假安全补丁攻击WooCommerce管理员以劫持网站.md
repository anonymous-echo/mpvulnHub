#  虚假安全补丁攻击WooCommerce管理员以劫持网站   
 FreeBuf   2025-04-28 10:32  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
一场大规模钓鱼攻击正针对WooCommerce用户，通过伪造安全警报诱使他们下载所谓的"关键补丁"，实则为植入WordPress后门的恶意程序。  
  
  
![WordPress](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38TVzXpKwEQ87HteZFlu25M8YegpybwFgS3xjEXfJEvr5vb2sazwRf84zjNoora77mJRxqBsQXn0w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**01**  
  
  
  
**恶意插件植入**  
  
  
根据Patchstack研究人员发现，上当受骗的用户在下载更新时，实际上安装的是恶意插件。该插件会：  
- 在网站上创建隐藏管理员账户  
  
- 下载Web Shell攻击载荷  
  
- 维持持久性访问权限  
  
此次攻击似乎是2023年末类似攻击的延续，当时攻击者同样以虚构漏洞的虚假补丁针对WordPress用户。研究人员指出，两次攻击使用了相同的Web Shell组合、完全一致的载荷隐藏方法以及相似的邮件内容。  
  
  
**02**  
  
  
  
**伪造安全警报**  
  
  
攻击者伪装成WooCommerce官方，使用"help@security-woocommerce[.]com"地址向网站管理员发送钓鱼邮件。邮件声称收件人网站正面临"未授权管理访问"漏洞攻击，并附带"立即下载补丁"按钮和详细安装指南。  
  
  
邮件内容节选："我们在2025年4月14日发现WooCommerce平台存在关键安全漏洞...4月21日的最新安全扫描确认该漏洞直接影响您的网站...强烈建议您立即采取措施保护商店和数据安全。"  
  
  
![钓鱼邮件](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38TVzXpKwEQ87HteZFlu25MaLydsqfglz93pes0KcVAMDuRARiarQ3b2t9MwV59eJTtyHesesia5ZPg/640?wx_fmt=jpeg&from=appmsg "")  
  
钓鱼邮件针对WooCommerce用户的钓鱼邮件来源：Patchstack  
  
  
**03**  
  
  
  
**同形异义字攻击**  
  
  
点击"下载补丁"按钮会跳转至高度仿冒WooCommerce的恶意网站"woocommėrce[.]com"。攻击者使用立陶宛字符"ė"(U+0117)替代字母"e"，实施同形异义字攻击，这种细微差别极易被忽视。  
  
  
![仿冒WooCommerce平台的恶意网站](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38TVzXpKwEQ87HteZFlu25Mtc5y4ZHfnVluic5GzCmrdQAB5OhxuKVb1j1mpvTksz0f4o2GnTOaTmA/640?wx_fmt=jpeg&from=appmsg "")  
  
仿冒WooCommerce平台的恶意网站仿冒WooCommerce平台的恶意网站来源：Patchstack  
  
  
**03**  
  
  
  
**感染后活动**  
  
  
  
当受害者安装了名为 “authbypass-update-31297-id.zip” 的虚假安全修复程序后，系统会生成一个名称随机的定时任务（cronjob）。该任务每分钟自动运行一次，目的是创建一个新的管理员级别的用户账号。  
  
  
随后，该插件会向 “woocommerce-services [.] com/wpapi” 发送 HTTP GET 请求，以此来注册已被感染的网站，并获取经过混淆处理的第二阶段恶意程序载荷。  
紧接着，系统的 “wp-content/uploads/” 目录下会被安装多个基于 PHP 的网页后门程序，包括 P.A.S.-Form、p0wny 和 WSO。  
  
  
Patchstack 分析指出，这些网页后门程序可让攻击者完全掌控网站，进而实施一系列恶意行为，如注入广告、将用户重定向至恶意网站、利用服务器组建分布式拒绝服务攻击（DDoS）僵尸网络、盗取支付卡信息，甚至还能运行勒索软件加密网站，以此向网站所有者索要赎金。  
  
  
为了躲避安全检测，该插件会将自身从插件列表中隐藏起来，同时也会隐藏其创建的恶意管理员账号。  
  
  
Patchstack 建议网站所有者仔细检查管理员账号，特别留意那些名称为 8 位随机字符的账号，还要关注异常的定时任务、名为 “authbypass-update” 的文件夹，以及向 woocommerce-services [.] com、woocommerce-api [.] com 或 woocommerce-help [.] com 发出的网络请求。  
  
  
还需注意的是，一旦这些威胁特征通过公开研究被曝光，攻击者往往会立即更改这些指标。因此，用户在进行安全检测时，切勿仅仅依赖于小范围的扫描。  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR39ibFdyjP3Qp8CEJxFWljbW1y91mvSZuxibf3Q3g2rJ32FNzoYfx4yaBmWbfwcRaNicuMo3AxIck2bCw/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651319086&idx=1&sn=e2ff862babd7662c4fa06b0e069c03f2&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651319171&idx=2&sn=9ae825f6633d32e60f1f2474c29e4e20&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651319257&idx=1&sn=a603c646a53e3a242a2e79faf4f06239&scene=21#wechat_redirect)  
  
  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR39ibFdyjP3Qp8CEJxFWljbW1uEIoRxNoqa17tBBrodHPbOERbZXdjFvNZC5uz0HtCfKbKx3o3XarGQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
  
  
  
  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icFibibPIGEfXsibI0C3or4BS5KDnCKUfVLVQGsc9BiaQTUsrwzfcianumzeLVcmibOmm2FzUqef2V6WPQQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38mFMbqsUOVbBDicib7jSu7FfibBxO3LTiafGpMPic7a01jnxbnwOtajXvq5j2piaII2Knau7Av5Kxvp2wA/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
