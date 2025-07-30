#  安全通告｜I Doc View在线文档预览系统远程代码执行漏洞   
 蓝鸟安全   2023-11-24 19:51  
  
#   
  
**一、漏洞描述**  
#   
  
  
iDocView是一个在线文档解析应用，文档预览采用响应式设计，在不同的终端（如笔记本、平板电脑或手机等）上预览时，文档会自动调整页面布局达到最佳效果，旨在提供便捷的文件查看和编辑服务。  
  
  
近日，中睿天下安全团队监测到I Doc View在线文档预览系统远程代码执行漏洞。由于攻击者可利用具有远程页面缓存功能的接口，在参数中填写预先准备的包含恶意文件的URL，使服务器下载恶意文件，获取服务器控制权限，进一步实现远程代码的执行。  
鉴于该漏洞影响较大，建议客户尽快做好自查及防护。  
  
  
**二、漏洞信息**  
  
#   
##   
  
**0****1**  
  
**漏洞详情**  
  
##   
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xAp8XWcCvbJBMh9GicLwCqJ0LhnYfotedia188icTGmm46EQBvibGtCAwOurvvsT4giavN30zhHJFpeP6w67c8CnCHg/640?wx_fmt=jpeg "")  
  
##   
  
**0****2**  
  
**漏洞复现**  
  
##   
  
  
中睿天下安全服务团队已复现此漏洞，复现截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xAp8XWcCvbJBMh9GicLwCqJ0LhnYfotedYDsSKz54MRrZqASIr9u3Sfa3SVKzQlTPSEKTSoyibeGhMdibbjOew6Mg/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xAp8XWcCvbJBMh9GicLwCqJ0LhnYfoted7gH4YzsINCOJ3TWRAj6fZL6rYCxic5JOo8qVE1gjjt3fNPQ97UVOChQ/640?wx_fmt=jpeg "")  
  
#   
  
**三、影响范围**  
  
  
**0****1**  
  
**影响版本范围**  
  
  
  
iDocView < 13.10.1_20231115  
  
##   
  
**0****2**  
  
**资产使用情况**  
  
##   
  
  
通过资产测绘系统发现，全球共8245个I Doc View在线文档预览系统的使用记录，其中中国有8128个使用记录。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xAp8XWcCvbJBMh9GicLwCqJ0LhnYfotedKvk0V5DfVNKEatMQD628KiamibZowsO6h8gT9t0PcutICTicUhHq8kxVA/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/xAp8XWcCvbKgLI39l0tAiamia4MgFeXMMKtc6TiaZoZ4TeSKuWNicIRXQ90UIQQTZEPrWqa1Xke60p3RbXwhLGqAJg/640?wx_fmt=png "")  
  
   
#   
  
**四、修复建议**  
  
  
目前官方目前已发布升级补丁进行漏洞修复，建议受影响用户尽快进行版本更新。  
  
  
官方下载链接：https://www.idocv.com/about.html  
  
