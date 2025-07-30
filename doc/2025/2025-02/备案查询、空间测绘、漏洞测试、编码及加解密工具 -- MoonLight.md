#  备案查询、空间测绘、漏洞测试、编码及加解密工具 -- MoonLight   
MKID1412  网络安全者   2025-02-18 16:00  
  
===================================  
免责声明请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。个人微信：ivu123ivu  
0x01 工具介绍  
使用 go1.20.2 语言进行开发，图形界面为GoQt，使用Qtdesigner进行界面绘制，exe执行程序位于deploy/windows/MoonLight.exe。主要功能为备案查询、鹰图和fofa空间测绘、常用编码及加密、nday扫描、发送请求包等。  
0x02 安装与使用  
备案数据查询域名对应的备案单位等信息，是在简单的信息收集时经常需要收集的信息，权重数据来源于爱站，可能需要用到api查询，可以去爱站获取权重api查询的key，免费的，不过只能查百度PC权重和百度移动权重。当然除此工具外平常也可以自己使用一些在线的查询工具如站长之家工具和爱站。  
  
![image-20240922160821899](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccwVWWtd6gHv4s92cwhR7vTz8FEyBFJRHGAN7GM7lztxukefZdpdDGXqibqckmM5noiaSeJPUROZKpfg/640?wx_fmt=png&from=appmsg "")  
  
空间测绘平台为鹰图和fofa，需要在设置中设置相应的key，可以设置多个，能自动进行切换。  
  
![image-20240922161239058](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccwVWWtd6gHv4s92cwhR7vTzfVhjcQePZccd2tgAJIYcciaLgOKiaEnTDpJGicrosLpjq2icpQejycZ53A/640?wx_fmt=png&from=appmsg "")  
  
![image-20240922161855783](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccwVWWtd6gHv4s92cwhR7vTz1PRdd7JOL2wbqmavq46fhkLWbEveQo07YeJHibjbpak6CfObVGbG8Aw/640?wx_fmt=png&from=appmsg "")  
  
编码加密有常见的编码、哈希以及DES、AES等加解密。  
  
![image-20240922162016231](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccwVWWtd6gHv4s92cwhR7vTzxcmefwATLzX1o3QlTPjZN8V720gZ88r4aPj3hictVdLYibnN317k0UuA/640?wx_fmt=png&from=appmsg "")  
  
漏洞测试这块目前只是一些nday的poc扫描，实现方法参考fscan，可以后续添加yaml格式的poc，对目标url先发起一次请求，根据webfingers.json中的正则匹配规则匹配指纹，能匹配到指纹则调用指定poc，否则调用所有poc进行扫描，也可以在设置中指定poc，请确保合法测试。  
  
![image-20240922162505495](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccwVWWtd6gHv4s92cwhR7vTzrhDsY09P1mPLUO1ibhpR5VJBB0YSM0EiaKV4SWhUGoPYUEq5NnRr1mjg/640?wx_fmt=png&from=appmsg "")  
  
扩展功能有发送请求包功能，其他功能可以后续添加到这里。  
  
![image-20240922162737439](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccwVWWtd6gHv4s92cwhR7vTziavicj9DI4HsfhicUsPFnn0VDHBDRrPEWh7ZWdn3xnzI2q4qhIzh7tEgw/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
  
  
  
**·****今 日 推 荐**  
**·**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccxialrndtia8ibKk0dL6rQRRmyXhKMgrZuCs6t3wuvkaufib4CTaJsib7ycYX1dQT4HOibpSYJMPRuLhkBA/640?wx_fmt=png&from=appmsg "")  
  
  
