#  利用 DoS 漏洞可瘫痪 Palo Alto 防火墙   
老布  FreeBuf   2024-12-31 10:59  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
Palo Alto Networks警告，称黑客正在利用CVE - 2024 - 3393拒绝服务漏洞，通过强制重启防火墙的方式，使其保护功能丧失。  
反复利用这一安全漏洞会让设备进入维护模式，必须手动干预才能恢复正常运行状态。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38HhiaXTrdT6htRicEufibw4pUuu9gOOdVYjNjg2AYG3Z4Cts6h6wibMvQibayicbZ2DBbIXRNYIoL4HiaJw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
公告指出：“Palo Alto Networks PAN - OS软件中的DNS安全功能存在一个拒绝服务漏洞，未经身份验证的攻击者能够经由防火墙的数据平面发送恶意数据包，从而造成防火墙重启。”  
  
   
  
**DoS漏洞正在被积极利用**  
  
  
## Palo Alto Networks表示，未经身份验证的攻击者可以向受影响的设备发送特制的恶意数据包来利用此漏洞。这一问题仅出现在启用了“DNS安全”日志记录的设备上，受CVE - 2024 - 3393影响的产品版本如下：  
> PAN - OS 10.1.14 - h8PAN - OS 10.2.10 - h12PAN - OS 11.1.5PAN - OS 11.2.3  
  
  
  
厂商确认该漏洞正在被积极利用，并且指出客户在防火墙阻止攻击者利用该漏洞发送的恶意DNS数据包时，出现了服务中断的情况。该公司已经在PAN - OS 10.1.14 - h8、PAN - OS 10.2.10 - h12、PAN - OS 11.1.5、PAN - OS 11.2.3以及后续版本中修复了这个漏洞。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38HhiaXTrdT6htRicEufibw4pUOPSC1M5eFiaEnr9VqGRibVBvqkibwiaWwsqpogZicFHBpvxrbtdMPHsZ36g/640?wx_fmt=jpeg&from=appmsg "")  
  
  
不过需要注意的是，受CVE - 2024 - 3393影响的PAN - OS 11.0版本不会收到补丁，因为该版本已于11月17日到达其生命周期终止（EOL）日期。对于无法立即更新的用户，Palo Alto Networks还发布了缓解问题的临时措施和步骤：  
  
  
对于未管理的下一代防火墙（NGFW）、由Panorama管理的NGFW或者由Panorama管理的Prisma Access：  
> 1. 导航至：Objects（对象）→Security Profiles（安全配置文件）→Anti - spyware（反间谍软件）→DNS Policies（DNS策略）→DNS Security（DNS安全），针对每个反间谍配置文件进行操作。  
> 2. 将所有已配置的DNS安全类别的日志严重性更改为“none”（无）。  
> 3. 提交更改，并且在应用修复之后恢复日志严重性设置。  
  
  
  
对于由Strata Cloud Manager（SCM）管理的NGFW：  
- 选项1：按照上述步骤直接在每台NGFW上禁用DNS安全日志记录。  
  
- 选项2：通过提交支持案例，在租户中的所有NGFW上禁用DNS安全日志记录。  
  
对于由Strata Cloud Manager（SCM）管理的Prisma Access：  
- 提交支持案例，以在租户中的所有NGFW上禁用DNS安全日志记录。  
  
- 如有需要，可在支持案例中请求加快Prisma Access租户的升级。  
  
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
  
