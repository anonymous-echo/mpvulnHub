> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwODc1NTgyMg==&mid=2247485814&idx=1&sn=638a006a1df5e6023e808865601dd5e6

#  一次非常规功能点的存储XSS  
Kn1vre  蓝云Sec   2025-06-14 16:01  
  
原文链接：  
https://forum.90sec.com/t/topic/2292  
  
一般XSS点是在留言、新增项等等地方，一般也都需要登录  
  
本文记录的试一次渗透中碰到的非常规的XSS功能点，无需登录  
  
所以也可以说是未授权XSS，并且直取admin  
  
漏洞功能点位于【**系统日志**  
】处  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7C9oVgOBoX4R1RE00tQDtQOrXPUsuV6CpURVic3IYYCKIEkIeAkRyyZQ35bQx85TTickoklwkw6azg/640?wx_fmt=png&from=appmsg "")  
  
此处记录并审计登录行为  
  
发现用户在登录时，用户名、IP等信息会被记录在此处，用户名可以根据POST请求包中的【username】字段进行改动，但是在测试过程中发现系统对该字段有进行特殊字符的限制，所以无法实现XSS  
  
但是后面发现对**IP字段**  
的输入却没有进行限制，在POST请求头中加入【x-forwarded-for】就可以任意自定义修改此处对应的【操作IP】  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7C9oVgOBoX4R1RE00tQDtQ5iaD9Iic6yh9kwticFdwTosDP4ODR9enSWgFtX8oaIEDbEGxjDaPiciarPg/640?wx_fmt=png&from=appmsg "")  
  
插入成功，管理员来到审核页面的时候就会触发XSS  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7C9oVgOBoX4R1RE00tQDtQbPLIBJXQQnyPic1aaBlcRj5XAjmXgia5onfic0lPUJmypsDaY9l0BA2uw/640?wx_fmt=png&from=appmsg "")  
  
这个系统对所有插入的数据几乎都做了编码、限制、替换，找了好久才找到这个位置  
  
所以测试或者说漏洞修复过程中，除了注意用户GET、POST的数据外，还需注意请求Header头里面的参数  
  
