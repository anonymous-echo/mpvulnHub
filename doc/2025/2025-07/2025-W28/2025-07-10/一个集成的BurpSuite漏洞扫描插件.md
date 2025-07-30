> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkxNzY5MTg1Ng==&mid=2247489945&idx=3&sn=fef11090d9dfd6c566185dcf5f5af6c0

#  一个集成的BurpSuite漏洞扫描插件  
菜狗  富贵安全   2025-07-10 00:50  
  
### 本着市面上各大漏洞探测插件的功能比较单一，因此与TsojanSecTeam成员决定在已有框架的基础上修改并增加常用的漏洞探测POC，它会以最少的数据包请求来准确检测各漏洞存在与否，你只需要这一个足矣。  
### 1、加载插件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/veA9QmcJk5lXuplcp027dc6ZecOewkYtrzgwT7A4c4fCelWLE6OUIiaWvnO5quvNcqaYx4HaZ6Y0CmdX46pKNkQ/640?wx_fmt=png&from=appmsg "")  
### 2、功能介绍  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/veA9QmcJk5lXuplcp027dc6ZecOewkYtEljx5Tibtx53B9CXMhFWStPic51UAQkGplzdYicTBVlF5MO064oPZymQg/640?wx_fmt=png&from=appmsg "")  
### 自定义黑名单，插件不扫描黑名单的url列表，进行Reg匹配优先级第一。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/veA9QmcJk5lXuplcp027dc6ZecOewkYtGIVHCtDdibXFrVw0WqowQUryTv8kIVBwZVrtqrqJEsYc23YOvHzrakQ/640?wx_fmt=png&from=appmsg "")  
### （2）主动探测  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/veA9QmcJk5lXuplcp027dc6ZecOewkYtxbyBlk5y8fJ137flVk8Xt7y5DdzGicE9C9KBbbsvkVI6pNpLbEVuoyA/640?wx_fmt=png&from=appmsg "")  
### 比如探测非根目录/，目录下面需要加/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/veA9QmcJk5lXuplcp027dc6ZecOewkYtaPQWnysMmgQQ9Gh7UiakX24LicHh78GgwRvdcTkZeQoD7qxY2ThmtX1g/640?wx_fmt=png&from=appmsg "")  
### 3、fastjson >=1.2.80探测  
  
（1）本地环境  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/veA9QmcJk5lXuplcp027dc6ZecOewkYtysvFQeicVZboWuDAZibvUsqvBm1ztaJt4j2BgynDMuP43kxEMs8URCoA/640?wx_fmt=png&from=appmsg "")  
### （2）预查询DNSlog接口  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/veA9QmcJk5lXuplcp027dc6ZecOewkYtLduhQbiabMR5o7O2vOG28LjicaTcAbTzWzHR2Yp1Ql9yNxKLgwxJrr3w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/veA9QmcJk5lXuplcp027dc6ZecOewkYtw160Lcgib3CQLBBViabiaRZkIFU8zSI9ISf36d3G3fRpVZR5NRM1w4lPw/640?wx_fmt=png&from=appmsg "")  
### （3）扫描  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/veA9QmcJk5lXuplcp027dc6ZecOewkYt0a4iaFibwUVINUkZV3540yeO3y48MgibricgUm3T0hfgNberdbicaDCaW9A/640?wx_fmt=png&from=appmsg "")  
### （4）判断准确版本  
  
1.2.80版本探测如果收到了两个dns请求，则证明使用了1.2.83版本，如果收到了一个 dns 请求，则证明使用了1.2.80版本。![](https://mmbiz.qpic.cn/sz_mmbiz_png/veA9QmcJk5lXuplcp027dc6ZecOewkYtclkNKrW4icJdBTvz78y2u7n2WaBxSg2ial6ZB8eNCUSYicudTVkpTfCCQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/veA9QmcJk5lXuplcp027dc6ZecOewkYtiaMXNQD1UXav35iaA7hic8FRGwDT5hKqVcptV0enlicquNPSVvf3pYbldg/640?wx_fmt=png&from=appmsg "")  
### 4、DNSLog查询漏报  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/veA9QmcJk5lXuplcp027dc6ZecOewkYtDovPFjPMMiaZLUIcAxPFgyxqFiclZ5vMia54UKaWSULHB1zYLZMJuIhBw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/veA9QmcJk5lXuplcp027dc6ZecOewkYtN6DibHWkpHoID7EYjtcEkaAorUqZVDn6j6UVev5kjLqXfnY0icYcxU4g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/veA9QmcJk5lXuplcp027dc6ZecOewkYticz5lIQyZLJuUua2sfO6oscR9z4tFDgyiaQ3gDZR7cTiaamiaXVLHcmiaIQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/veA9QmcJk5lXuplcp027dc6ZecOewkYtmf7MXwQjBVdsntaib6wbHU4qcEe3rrQUNIntyc58CicoUOxLtrdHYrzw/640?wx_fmt=png&from=appmsg "")  
注意⚠️：扫描结束后才会在BurpSuite的Target、Dashboard模块显示高危漏洞，进程扫描中无法进行同步，但可以在插件中查看（涉及到DoPassive方法问题）。![](https://mmbiz.qpic.cn/sz_mmbiz_png/veA9QmcJk5lXuplcp027dc6ZecOewkYtibBID8KafNWbEO3ow9KK9Gg1bSic7xK0JlhibYKA8dDEpIvJT6aW9gn8w/640?wx_fmt=png&from=appmsg "")  
  
### Update  
  
更新说明 - v1.4.6 新增XyzDnsLog平台，删除不可用的DnsLog，由于国内政策问题，建议使用Ceye dnslog平台; 修复适配Burp Suite Pro 2024年度版本报错问题; 优化发包代码逻辑，更新插件稳定性。 更新说明 - v1.4.5 增加nacos漏洞被动扫描，CVE-2021-29441 & QVD-2023-6271 ; 增加jpath主动模块化扫描，集合SpringBoot Env、Druid、Swagger 相关无害化POC; 更新dnslog平台，删除不可用的dnslog，默认设置Ceye dnslog平台; 修复新版本BurpSuite版本报错问题 #23 ; 修复删除测试垃圾代码，优化插件稳定性。  
### 更新说明 - v1.4.4  
  
优化代码结构；  
  
修复weblogic弱口令误报bug；  
  
增加otf后缀不扫描规则；  
  
删除asix/happaxis.jsp扫描规则；  
  
增加sql语法错误的页面回显扫描模块，只显示sql错误显示（参数后面增加单引号、双引号、反斜线，去查看有没有SQL错误语句）  
  
更新说明 - v1.4.3 修复首次加载插件占用过多资源的问题造成假死进程状态。  
  
增加dnslog：DNSlog平台Xssx1，首次加载插件使用Ceye，后续启动则默认使用上次应用的dnslog，若网络环境较好，推荐使用Xssx1、Microsoftz方式。  
  
增加主动/被动 Ueditor .net 文件上传扫描模块。  
  
更新说明 - v1.4.2 1.增加Ceye dnslog平台，默认加载为Microsoftz，需要手动加载Ceye后，下次再打开将自动加载上次Apply应用的dnslog。  
  
后台回复  
burp插件  
即可获取下载链接  
  
