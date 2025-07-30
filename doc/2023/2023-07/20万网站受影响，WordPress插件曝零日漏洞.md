#  20万网站受影响，WordPress插件曝零日漏洞   
看雪学苑  看雪学苑   2023-07-11 17:59  
  
近日，网络安全研究人员发现广泛使用的WordPress网站的Ultimate Member插件（用于简化用户注册及登录流程）存在0day漏洞，该插件目前已安装在全球超过20万个活跃网站上。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8Fv6UWsuJA1I393wiaJr3CUrzxibqpKVfhCAxibbNwm4HsXMcjw7WuaKQULQbPp5o8ATScgia1NNBibklQ/640?wx_fmt=png "")  
  
  
  
该0day（CVE-2023-3460，CVSSv3.1评分9.8）使得黑客能够在目标网站上获取提升的权限，可能导致未经授权的访问以及对受影响网站的控制。更严重的是，已经有攻击者在利用此漏洞进行攻击。  
  
  
据了解，Ultimate Member插件通过使用预定义的用户元数据键列表来运行，其中存在安全绕过的空间。Ultimate Member的黑名单逻辑与WordPress处理元数据键的方式存在差异，这使得攻击者有可能欺骗插件更新一些不应该更新的内容，比如“wp_capabilities”（用于存储用户的角色和权限）。未经身份验证的攻击者能够利用Ultimate Member插件中的这个特权提升漏洞来创建具有管理员权限的恶意账户，从而完全接管受影响的网站。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8Fv6UWsuJA1I393wiaJr3CUrCJ7icR8srcPpUaLOSKD8MW6YhxFIS3eW6udmILsbuXvXKTrwKIibzpTg/640?wx_fmt=png "")  
  
  
WPScan的博客表明，这些攻击至少从6月初以来一直在进行，一些用户已经观察到并报告了相关可疑活动，如未经授权的管理员账户的创建。  
  
  
作为对此漏洞的回应，Ultimate Member插件的开发者立即发布了一个新版本2.6.4，然而仍然存在绕过此补丁的方式，漏洞仍能够被利用。在之后发布的2.6.7版本中，此问题终于得到完全的修复。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8Fv6UWsuJA1I393wiaJr3CUr0JmEibUuHRUPub9AR4NHs0p9o8ibog7CeTYH9YgmlfClG1E5fEA29AeQ/640?wx_fmt=png "")  
  
  
  
Ultimate Member插件开发者建议，受影响的用户最好按照以下步骤向其网站添加安全措施：  
  
① 查看并删除未知管理员帐户；  
  
② 重置所有用户密码（包括管理员账户密码）；  
  
③ 安装并激活WPScan、WordFence等安全插件；  
  
④ 确保网站部署SSL证书；  
  
⑤ 创建网站文件和数据库的每日备份；  
  
⑥ 向网站成员/客户发送关于此事件的通知及密码重置建议。  
  
  
  
编辑：左右里  
  
资讯来源：wpscan、ultimatemember  
  
转载请注明出处和本文链接  
  
  
**每日涨知识**  
  
密码学  
（cryptography）  
  
应用于数据的算法，用于确保机密性、完整性、身份认证和/或不可否认性。  
  
  
﹀  
  
﹀  
  
﹀  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8E9S6vNnUMRCOictT4PicNGMgHmsIkOvEno4oPVWrhwQCWNRTquZGs2ZLYic8IJTJBjxhWVoCa47V9Rw/640?wx_fmt=gif "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8E9S6vNnUMRCOictT4PicNGMgHmsIkOvEno4oPVWrhwQCWNRTquZGs2ZLYic8IJTJBjxhWVoCa47V9Rw/640?wx_fmt=gif "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8E9S6vNnUMRCOictT4PicNGMgHmsIkOvEno4oPVWrhwQCWNRTquZGs2ZLYic8IJTJBjxhWVoCa47V9Rw/640?wx_fmt=gif "")  
  
**球在看**  
  
****  
****  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/1UG7KPNHN8FxuBNT7e2ZEfQZgBuH2GkFjvK4tzErD5Q56kwaEL0N099icLfx1ZvVvqzcRG3oMtIXqUz5T9HYKicA/640?wx_fmt=gif "")  
  
戳  
“阅读原文  
”  
一起来充电吧！  
  
