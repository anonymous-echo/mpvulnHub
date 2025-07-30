#  【漏洞预警】泛微 E-cology 远程代码执行漏洞   
原创 大荒Sec  太乙Sec实验室   2025-04-25 07:12  
  
**免责声明****：**  
本公众号 **太乙Sec实验室**  
所提供的实验环境均是本地搭建，仅限于**网络安全研究与学习**  
。旨在为安全爱好者提供技术交流。任何个人或组织因传播、利用本公众号所提供的信息而进行的操作，所导致的直接或间接后果及损失，均由使用者本人负责。**太乙Sec实验室**  
及作者对此不承担任何责任  
  
  
漏洞预警  
  
e-cology 是上海泛微网络推出的企业级协同办公自动化系统，面向中大型企业提供智能化、平台化、全程数字化的信息化解决方案，核心目标是提升组织协同效率与管理水平。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tHlQeib8sz1J6y4X2a3yyT5NsYm9hPcgia45D5732AIflwbpedqGVu3wL8U9znACnhSWiclmxdxaR97OopqcPCaaA/640?wx_fmt=png&from=appmsg "")  
  
攻击者通过构造恶意请求→突破身份认证限制→向数据库写入恶意数据→利用 Ole 组件将数据导出为 Webshell→执行任意系统命令→获取服务器最高权限  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tHlQeib8sz1J6y4X2a3yyT5NsYm9hPcgiaYKmp5PXEIKEehX2tDKwRvYUe6Okj6xV7c8RBoC6OPzB6Llicru9QpHQ/640?wx_fmt=png&from=appmsg "")  
  
一、漏洞基础信息  
<table><tbody><tr style="height: 33px;"><td data-colwidth="99" width="200" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><strong><span style="font-size: 16px;color: rgba(0, 0, 0, 0.85) !important;background-color: rgb(239, 240, 241);"><span leaf="">字段</span></span></strong></p></td><td data-colwidth="486" width="486" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><strong><span style="font-size: 16px;color: rgba(0, 0, 0, 0.85) !important;background-color: rgb(239, 240, 241);"><span leaf="">详情</span></span></strong></p></td></tr><tr style="height: 33px;"><td data-colwidth="99" width="200" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><strong><span style="font-size: 16px;color: rgba(0, 0, 0, 0.85) !important;background-color: rgb(239, 240, 241);"><span leaf="">CNVD-ID</span></span></strong></p></td><td data-colwidth="486" width="486" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><span style="font-size: 16px;color: rgba(0, 0, 0, 0.85) !important;background-color: rgb(239, 240, 241);"><span leaf="">CNVD-2025-07886</span></span></p></td></tr><tr style="height: 33px;"><td data-colwidth="99" width="200" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><strong><span style="font-size: 16px;color: rgba(0, 0, 0, 0.85) !important;background-color: rgb(239, 240, 241);"><span leaf="">公开日期</span></span></strong></p></td><td data-colwidth="486" width="486" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><span style="font-size: 16px;color: rgba(0, 0, 0, 0.85) !important;background-color: rgb(239, 240, 241);"><span leaf="">2025-04-22</span></span></p></td></tr><tr style="height: 33px;"><td data-colwidth="99" width="200" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><strong><span style="font-size: 16px;color: rgba(0, 0, 0, 0.85) !important;background-color: rgb(239, 240, 241);"><span leaf="">危害级别</span></span></strong></p></td><td data-colwidth="486" width="486" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><span style="font-size: 16px;color: rgba(0, 0, 0, 0.85) !important;background-color: rgb(239, 240, 241);"><span leaf="">高（CVSS 向量：AV:N/AC:L/Au:N/C:C/I:C/A:C，表明网络可访问、低复杂度利用、无需认证、完全影响机密性 / 完整性 / 可用性）</span></span></p></td></tr><tr style="height: 33px;"><td data-colwidth="99" width="200" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><strong><span style="font-size: 16px;color: rgba(0, 0, 0, 0.85) !important;background-color: rgb(239, 240, 241);"><span leaf="">漏洞类型</span></span></strong></p></td><td data-colwidth="486" width="486" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><span style="font-size: 16px;color: rgba(0, 0, 0, 0.85) !important;background-color: rgb(239, 240, 241);"><span leaf="">命令执行漏洞（通过 SQL 注入链实现远程代码执行）</span></span></p></td></tr><tr style="height: 33px;"><td data-colwidth="99" width="200" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><strong><span style="font-size: 16px;color: rgba(0, 0, 0, 0.85) !important;background-color: rgb(239, 240, 241);"><span leaf="">影响产品</span></span></strong></p></td><td data-colwidth="486" width="486" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><span style="font-size: 16px;color: rgba(0, 0, 0, 0.85) !important;background-color: rgb(239, 240, 241);"><span leaf="">上海泛微网络科技股份有限公司 e-cology &lt; 10.74</span></span></p></td></tr><tr style="height: 33px;"><td data-colwidth="99" width="200" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><strong><span style="font-size: 16px;color: rgba(0, 0, 0, 0.85) !important;background-color: rgb(239, 240, 241);"><span leaf="">收录 / 更新时间</span></span></strong></p></td><td data-colwidth="486" width="486" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><span style="font-size: 16px;color: rgba(0, 0, 0, 0.85) !important;background-color: rgb(239, 240, 241);"><span leaf="">2025-04-22（同步更新）</span></span></p></td></tr></tbody></table>  
  
**二、影响范围**  
  
产品版本所有 e-cology 版本 < 10.74（包含 10.74 之前的长期支持版本及历史版本）  
  
部署在互联网边界的 e-cology 服务器（暴露公网 IP 的资产风险极高）。  
  
  
三、修复方案  
  
官方修复（优先推荐）  
  
升级至   
e-cology 10.74 及以上版本  
，官方已在该版本中修复 SQL 注入及命令执行风险：  
  
  
补丁下载链接  
```
https://www.weaver.com.cn/cs/securityDownload.html?src=cn
```  
  
操作建议  
：  
1. 备份数据库与系统文件后进行升级  
  
1. 验证升级后版本号（路径：系统管理→系统信息→版本号）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tHlQeib8sz1J6y4X2a3yyT5NsYm9hPcgiaV9Gly1uIrh2iaOIVQ4D3vFC6p5BicbktVY4qRA5u4CuxUkPJRZoia9iang/640?wx_fmt=png&from=appmsg "")  
  
  
往期精彩回顾  
  
[记一次在校园网中的Mysql趣味udf提权](https://mp.weixin.qq.com/s?__biz=Mzk0Mzc2MDQyMg==&mid=2247486522&idx=1&sn=ad9190964e79bec4d7a944974d4b68f1&scene=21#wechat_redirect)  
  
  
[记一次某校情平台水平越权，导致全校学生信息泄露](https://mp.weixin.qq.com/s?__biz=Mzk0Mzc2MDQyMg==&mid=2247486513&idx=1&sn=fffe6f1b497c681987750137b266e65f&scene=21#wechat_redirect)  
  
  
**关注我****，了解****更多知识，别忘****了关注****+点赞****哦！******  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RITPxDQz30icticGDszvMCTbvDxbl8zxyibqkfOTIRXJQVU3YEHicR6AiatHvlnPic7qayibiazKoJV54NVDMmL1uVqsGg/640?wx_fmt=other&random=0.008279855111830159&random=0.8417589579850686&random=0.7406363082812077&random=0.10974797073162001&random=0.07292006660739969&wxfrom=5&wx_lazy=1&wx_co=1&random=0.9329563926201925&random=0.7721899576088909&random=0.8732144113576208&random=0.19158149965875793&random=0.14234663701611816&random=0.6197239709294833&random=0.6087404282162256&random=0.7816651464380318&random=0.6382235312520264&random=0.18529992036868959&random=0.8108904783265143&random=0.8471140121001628&random=0.08898610680286101&random=0.008507273801011683&random=0.9647940082061903&random=0.49839411124559185&random=0.36416103289090485&random=0.8610727679390984&random=0.4202445756317146&random=0.5658152415600335&random=0.05215623887101817&random=0.054673954102818945&random=0.7636185446317116&random=0.6630448098148167&random=0.6555189201793772&tp=webp "")  
  
  
