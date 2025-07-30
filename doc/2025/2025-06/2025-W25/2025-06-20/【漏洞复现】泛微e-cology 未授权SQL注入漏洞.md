> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI4MjkxNzY1NQ==&mid=2247485970&idx=1&sn=1c7e97d2e1a8c9348506e82951046672

#  【漏洞复现】泛微e-cology 未授权SQL注入漏洞  
稻草人  玄武盾网络技术实验室   2025-06-20 16:28  
  
**“**  
 对我们感兴趣的话就点个关注吧！**”**  
  
## 免责声明：本文仅供安全研究与学习之用，严禁用于非法用途，违者后果自负。  
## 漏洞介绍  
  
泛微协同管理应用平台(e-cology)是一套兼具企业信息门户、知识文档管理、工作流程管理、人力资源管理、客户关系管理、项目管理、财务管理、资产管理、供应链管理、数据中心功能的企业大型协同管理平台。受影响版本中，/js/hrm/getdata.jsp 存在 SQL 注入漏洞，攻击者可利用该漏洞向数据库中注入任意SQL命令。  
## 漏洞版本  
  
< v10.75  
## 漏洞复现  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJI2BvgvNFiblzjtlvnCZy0X4QGlMXYUfdPnA7vaptrjMaNUdhyZTt4Z6FTMOahYQ1iawkL7gd2ByTYA/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
POC:  
  
(这微信页面直接复制代码格式会乱，可以浏览器打开复制)  

```
/js/hrm/getdata.jsp?cmd=savect
/js/hrm/getdata.jsp?cmd=initChart
```

  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJI2BvgvNFiblzjtlvnCZy0X4nNib0iaib7TLdyOfMjIaHfGuN0tia7GAfaAdmsOF1UxnxIpK1vmZHaO2ug/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
## 漏洞分析  
  
getdata.jsp中调用 weaver.hrm.common.AjaxManager.getData 方法  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJI2BvgvNFiblzjtlvnCZy0X4a29ZcWzyNSx2whSW9kBcnaV5sveZPfNYXXmIiadCcWUqYjceJnEKvYQ/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
进入
```
classbean/weaver/hrm/common/AjaxManager.class
```

  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJI2BvgvNFiblzjtlvnCZy0X40dCib70FXbR1NQ41e5DOZq1YdQk2suhQ31t02JkBoXl63Mhf3icibqFcQ/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
根据cmd的值来进入if条件，进入savect /initChart 中调用hrmChartSetManager.get  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJI2BvgvNFiblzjtlvnCZy0X4rV01n3J4ibNurPFE0EhA4fc64GDOFYE87063EicdHbyRvB06hII4EQNQ/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJI2BvgvNFiblzjtlvnCZy0X4OrNKhomHNibs0nHaVnTXMJpfkyMDt3wCibgtibrxJESkI6IykBGpZtDvA/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
跟进
```
classbean/weaver/hrm/chart/dao/HrmChartSetDao.class
```

  
进入  
- 创建HashMap存储查询参数  
- 将传入的paramComparable作为"id"参数值放入Map  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJI2BvgvNFiblzjtlvnCZy0X4RVAk55oGgIOFPwBezAYj2XmlcIseNVDSXpkfE2jUTXM7jD11Yz6SicA/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
获取id的值进行数据拼接  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJI2BvgvNFiblzjtlvnCZy0X4nfEtibKqW0yPQ9ZeWG1ib3IfHN2S6SeWyHtoOYumV8wZTvL5qSZFb8rQ/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
## 修复意见  
  
官方已发布升级补丁包，支持在线升级和离线补丁安装，下载地址：  
  
https://www.weaver.com.cn/cs/securityDownload.html?src=cn  
  
  
编辑说不点「推荐」就扣我鸡腿！救救孩子吧。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/UM0M1icqlo0knIjq7rj7rsX0r4Rf2CDQylx0IjMfpPM93icE9AGx28bqwDRau5EkcWpK6WBAG5zGDS41wkfcvJiaA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
