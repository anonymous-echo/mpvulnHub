#  Palo Alto Networks披露PAN-OS防火墙「满分」漏洞细节   
Zicheng  FreeBuf   2024-04-22 18:48  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
自3 月 26 日以来，Palo Alto Networks防火墙产品受到了疑似由国家支持的黑客攻击，近日，该企业披露了黑客进行攻击所利用漏洞的更多细节。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibPaXXzibTQWIAW7icz3iaAesgkYrJ5ic8DcafT0JtMuicjrGTpichKoFYibwxYFiaskIxibZ5jhTtJibKctibuQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
该漏洞被追踪为 CVE-2024-3400，CVSS 评分达10分，具体涉及PAN-OS 10.2、PAN-OS 11.0 和 PAN-OS 11.1 防火墙版本软件中的两个缺陷。  
  
  
在第一个缺陷中，GlobalProtect 服务在存储会话 ID 格式之前没有对其进行充分验证。Palo Alto Networks 产品安全高级总监 Chandan B. N. 表示，这使得攻击者能够用选择的文件名存储一个空文件。第二个缺陷被认为是系统生成的文件将文件名作为了命令的一部分。  
  
  
值得注意的是，虽然这两个缺陷本身都不够严重，但当它们组合在一起时，就可能导致未经验证的远程 shell 命令执行。  
  
  
Palo Alto Network表示，利用该漏洞实施零日攻击的攻击者实施了两阶段攻击，以便在易受影响的设备上执行命令。该活动被命名为Operation MidnightEclipse，涉及发送包含要执行命令的特制请求，然后通过名为 UPSTYLE 的后门运行。  
  
  
在攻击的第一阶段，攻击者向 GlobalProtect 发送精心制作的 shell 命令而非有效的会话 ID，导致在系统上创建一个空文件，文件名由攻击者命名为嵌入式命令；在第二阶段，定时运行系统作业会在命令中使用攻击者提供的文件名，进而让攻击者提供的命令能以更高的权限执行。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibPaXXzibTQWIAW7icz3iaAesgxBJSx87iaAVf9X3IBrK2JcsI9HmVk7VicookJqMuI8ZPRfQaKXic54K2A/640?wx_fmt=jpeg&from=appmsg "")  
  
攻击示意图  
  
  
利用这种方式，攻击者就能将该漏洞武器化，且不需要在设备上启用遥测功能就能对其进行渗透。  
  
  
目前Palo Alto Networks已经列出了需要打补丁的PAN-OS防火墙系统版本：  
  
- PAN-OS 10.2.9-h1  
  
- PAN-OS 10.2.8-h3  
  
- PAN-OS 10.2.7-h8  
  
- PAN-OS 10.2.6-h3  
  
- PAN-OS 10.2.5-h6  
  
- PAN-OS 10.2.4-h16  
  
- PAN-OS 10.2.3-h13  
  
- PAN-OS 10.2.2-h5  
  
- PAN-OS 10.2.1-h2  
  
- PAN-OS 10.2.0-h3  
  
- PAN-OS 11.0.4-h1  
  
- PAN-OS 11.0.4-h2  
  
- PAN-OS 11.0.3-h10  
  
- PAN-OS 11.0.2-h4  
  
- PAN-OS 11.0.1-h4  
  
- PAN-OS 11.0.0-h3  
  
- PAN-OS 11.1.2-h3  
  
- PAN-OS 11.1.1-h1  
  
- PAN-OS 11.1.0-h3  
  
鉴于 CVE-2024-3400 漏洞正被积极滥用以及概念验证 （PoC） 漏洞利用代码的可用性，建议用户尽快采取措施进行修补，以防范潜在威胁。  
  
  
美国网络安全和基础设施安全局 （CISA） 还将该漏洞添加到其已知利用漏洞 （KEV） 目录中，命令联邦机构在 2024 年 4 月 19 日之前保护其设备。  
  
  
根据 Shadowserver 基金会共享的信息，大约 22542 台暴露于互联网的防火墙设备可能容易受到该漏洞的攻击。截至 2024 年 4 月 18 日，大多数设备位于美国、日本、印度、德国、英国、加拿大、澳大利亚、法国和中国。  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复“加群”，申请加入群聊  
】  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ61icYlLmBLDpdYEZ7nIzpGovpHjtxITB6ibiaC3R5hoibVkQsVLQfdK57w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
> https://thehackernews.com/2024/04/palo-alto-networks-discloses-more.html  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247493362&idx=1&sn=39c9b1c4d709e5ad0babb44995b0e412&chksm=ce1f1c6df968957be704d2843b3f448b252d2a2e1b5271efa486c3e57819849e0e287b04568b&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247493318&idx=1&sn=02dc5120e00a3d6759be8fcf1b49ec0a&chksm=ce1f1c59f968954fd868b2f8cefa0e8bc5dd703c36dd6db4fc03923be36783a7d4cc791c18b6&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
