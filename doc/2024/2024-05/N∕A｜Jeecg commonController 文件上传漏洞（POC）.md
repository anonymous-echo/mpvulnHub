#  N/A｜Jeecg commonController 文件上传漏洞（POC）   
alicy  信安百科   2024-05-01 20:59  
  
**0x00 前言**  
  
  
JeecgBoot是一款基于BPM的低代码平台！前后端分离架构 SpringBoot 2.x，SpringCloud，Ant Design&Vue，Mybatis-plus，Shiro，JWT，支持微服务。强大的代码生成器让前后端代码一键生成，实现低代码开发！  
  
  
  
**0x01 漏洞描述**  
  
  
由于 /api 接口鉴权时未过滤路径遍历，攻击者可构造包含 ../ 的url绕过鉴权。攻击者可构造恶意请求利用 commonController 接口进行文件上传攻击实现远程代码执行。  
  
  
**0x02 CVE编号**  
  
  
无  
  
  
  
**0x03 影响版本**  
  
  
无  
  
  
  
**0x04 漏洞详情**  
  
****  
POC：  
  
https://forum.butian.net/share/2836  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Whm7t4Je6urkUWohlvXmWLdpicDd05lAa2e989JmR2ibgOzCD2wDFsRGflYIDWe3d8TZpYhdiaXuWaqdbdSCxr8Wg/640?wx_fmt=png&from=appmsg "")  
  
  
  
**0x05 参考链接**  
  
  
https://forum.butian.net/s  
hare/2836  
  
  
https://github.com/jeecgboot/jeecg  
  
  
  
  
推荐阅读：  
  
  
[CVE-2023-49442｜Jeecg远程代码执行漏洞](http://mp.weixin.qq.com/s?__biz=Mzg2ODcxMjYzMA==&mid=2247484831&idx=3&sn=b43df5e2ae8940030744688ba471d6a8&chksm=cea96c46f9dee5509e54be6f65b917039760c8956b64f268996112abfe1669c1c8475af13181&scene=21#wechat_redirect)  
  
  
  
[Jeecg-boot JDBC任意代码执行漏洞](http://mp.weixin.qq.com/s?__biz=Mzg2ODcxMjYzMA==&mid=2247484447&idx=1&sn=2d4efae553a088816f93bf535a9453ca&chksm=cea96dc6f9dee4d07f245e6792bc3844ed0d9e150c7dfa943995a4fabb0ce3a049d74d23d938&scene=21#wechat_redirect)  
  
  
  
[CVE-2024-3721｜TBK DVR硬盘录像机命令注入漏洞（POC）](http://mp.weixin.qq.com/s?__biz=Mzg2ODcxMjYzMA==&mid=2247485230&idx=3&sn=e5dde220eecc73505d3580be8646957f&chksm=cea96ef7f9dee7e100ff58c23782d7db4dc9dc62ff2b79cc7316fd94d3af9ac93c05b89dc089&scene=21#wechat_redirect)  
  
  
  
  
  
  
Ps：国内外安全热点分享，欢迎大家分享、转载，请保证文章的完整性。文章中出现敏感信息和侵权内容，请联系作者删除信息。信息安全任重道远，感谢您的支持![](https://mmbiz.qpic.cn/mmbiz_png/Whm7t4Je6urTIficI8UhQibwpYWx4ic7Bk40AJlXrgx3icofWCbd5cbJFheld132R8exvlHnicn0AUjHLmVok4wV9qA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
！！！  
  
  
**本公众号的文章及工具仅提供学习参考，由于传播、利用此文档提供的信息而造成任何直接或间接的后果及损害，均由使用者本人负责,本公众号及文章作者不为此承担任何责任。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Whm7t4Je6uqQ24S6worK6npevNP8p1uPc9jQeMAib2iaibBnibOzFaIbD0KlvsEtUAmL3xdbJJnWk74Y1KfBcIazzw/640?wx_fmt=png "")  
  
  
