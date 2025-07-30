#  安天智甲EDR紧急响应输入法高危漏洞   
 安天集团   2024-08-02 18:04  
  
点击上方"蓝字"  
  
关注我们吧！  
  
  
##   
  
**0****1**  
  
**漏洞概述**  
  
  
2024年8月1日，网传发现某第三方输入法存在绕过windows10、windows11登录系统权限执行任意命令的漏洞。安天攻防实验室初步推断该方法适用于主流的windows10、windows11等版本操作系统，已在Windows10、windows11上复现。  
  
通过利用该漏洞，该输入法可绕过系统登录，以system系统权限执行任意命令、读写文件、访问移动介质。  
  
需要关注的是，由于第三方输入法有较高的系统权限，且目前多数第三方输入法有较多的附加功能，因此安天攻防实验室怀疑此漏洞会影响多种第三方输入法。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/krU5D4C1q6T5MrfSgZSqVaPlvIibNujJSIkP8doXrhI8CWE9InHIxdIeTFJ6IQE93ibFiccUJMzOiadQ4GeicPfqtwg/640?wx_fmt=png&from=appmsg "")  
  
图1 SYSTEM权限执行任意指令验证  
  
**在本地攻击利用场景下，**  
该漏洞攻击成功率非常高。  
  
**在远程攻击利用场景下，**  
若攻击者通过RDP机制登录Windows主机，并且Windows主机关闭了网络级身份验证（NLA）机制，则攻击成功率很高。所幸目前多数Windows操作系统中，均默认开启NLA验证。  
  
  
**0****2**  
  
**漏洞修复**  
###   
  
**2.1 官方修复情况**  
  
目前微软对这一问题尚无信息发出。  
  
输入法官方官网暂未发布更新修复信息，但应该已经进行了内部应急修复，部分用户场景已经较难复现该漏洞。  
  
但如果存在内网计算机无法及时升级该输入法的情况，依旧可能受到这一漏洞的影响。  
  
**2.2 人工缓解方法**  
  
在缺少官方修复方案时，安天建议针对这一漏洞采用人工缓解措施：  
- 做好内部物理安全防护，避免非授权人员接触内部计算机系统。  
  
- 非必要不开启RDP登录权限，并严格配置NLA机制。  
  
- 建议必须开放远程服务的主机，临时卸载第三方输入法，暂时使用系统默认输入法。  
  
设置NLA机制的方式如下图2所示，对不需要远程登录的系统，要选择“不允许远程连接到此计算机”。对必须开启远程RDP登录的计算机，在选择“允许远程连接到此计算机”的同时，务必确认下方“仅允许运行使用网络级别身份验证的远程桌面的计算机连接”被选中打钩。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/krU5D4C1q6T5MrfSgZSqVaPlvIibNujJSdJVtZtQk0wVlicYYPTa5684ucBr1XuzGBzwYHKHMm3SmEOlVSuJibLow/640?wx_fmt=png&from=appmsg "")  
  
图2 设置Windows的NLA机制  
  
  
  
## 2.3 使用安天智甲终端检测与响应系统防御此漏洞  
##   
  
  
针对上述漏洞，安天智甲终端检测与响应系统在V5.0.5.1版本中增加了此项漏洞防御能力，同时针对老版本客户端已发布产品升级包，请相关用户将智甲客户端升级至最新版，以增加对上述漏洞的防御能力。  
  
安天可以启动拦截非微软系统cmd主防策略来拦截同类供给，但由于该策略可能影响第三方软件安装，如果需要进行策略调整的客户可以和安天联系。我们后续版本将在EDR管理开放该配置点和并提供针对性签名规则设置。  
  
如需升级包，请联系400-840-9234。  
  
升级后的智甲产品可有效防御上述漏洞行为。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/krU5D4C1q6T5MrfSgZSqVaPlvIibNujJSu6uBMiasYc8T2nlOX1xxt0PqMj7vjfF0AOmaMEMUdN7gQl43BqNEhkA/640?wx_fmt=png&from=appmsg "")  
  
图3 智甲终端检测与响应系统告警  
  
  
  
**03**  
  
**安全声明**  
  
  
本安全公告仅用来描述可能存在的安全问题，安天不为此安全公告提供任何保证或承诺。使用此安全公告应遵守相关法律法规规定。由于传播、利用此安全公告所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，安天以及安全公告作者不为此承担任何责任。  
  
安天拥有对此安全公告的修改和解释权。如欲转载或传播此安全公告，必须保证此安全公告的完整性，包括版权声明等全部内容。未经安天允许，不得任意修改或者增减此安全公告内容，不得以任何方式将其用于商业目的。  
  
  
**04**  
  
**参考信息**  
##   
##   
##   
  
**4.1 关于智甲终端检测与响应系统产品**  
  
安天智甲终端检测与响应系统是一款面向办公机、服务器、专用设备等资产的终端安全防护产品。智甲具有资产管理、风险检测、威胁检测与处置、微隔离与事件调查等多种防护能力，以此打造端点识别、塑造、防护、检测和响应的安全闭环运营体系，实现终端安全有效防护。  
##   
  
![](https://mmbiz.qpic.cn/mmbiz_gif/krU5D4C1q6Qp5ibY5FNyUU9Xg9IkGU3RvjPcITwHD6HnXDQo0FicqNrZIxAiaexKsIIID6F2o8doIhgmwfcxZNToA/640?wx_fmt=gif "")  
  
**往期回顾**  
  
  
[](http://mp.weixin.qq.com/s?__biz=MjM5MTA3Nzk4MQ==&mid=2650206285&idx=1&sn=2914ede1c58fd13f877b8ff3d1975be2&chksm=beb9537f89ceda696be771c195f85f8f6d7f6acb28d6d730f8fb945e6826e6b60dff33f2c322&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MjM5MTA3Nzk4MQ==&mid=2650202104&idx=1&sn=f18c0cf27d5f51cb2f7e6de1a17b5dc1&chksm=beb97cca89cef5dcbfe386ed8e4430f9d86f5f2f7cd3b9cbe52a4b985cb4cdef1dad9a8adbc3&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MjM5MTA3Nzk4MQ==&mid=2650188804&idx=1&sn=9cf5ecd1b102a11c2252c928dc999c19&chksm=beb90f3689ce86200c9bedb9a51f26818bb836b8be2c3883650d4dff944b280b09ae299dcf1d&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MjM5MTA3Nzk4MQ==&mid=2650187497&idx=1&sn=e0dcd78df8f12af58aedc51194c1f801&chksm=beb905db89ce8ccdbc7581557376889b857d84d28e2934b7d74fa060bb590b6daae451aefbe2&scene=21#wechat_redirect)  
  
  
