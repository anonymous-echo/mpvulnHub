> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwODc1NTgyMg==&mid=2247487331&idx=1&sn=5b06a2aa3e65950b4ba81a6d92dd1c67

#  【HW漏洞复现】e脸通综合管理平台文件上传漏洞  
原创 新极客  蓝云Sec   2025-07-15 02:31  
  
测绘语法  

```
360quake资产测绘：
title: &#34;e脸通综合管理平台&#34;
```

  
漏洞复现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK4JE3zBrw3XnOApuE6y4Tg2fLYtBQwODY2lxo8XnJdhINTWs3Vic1XQDXKeMPtvqxS5EBUGF3NqnjA/640?wx_fmt=png&from=appmsg "")  
  
访问http://ip/manage/加上响应包中path字段路径即可  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK4JE3zBrw3XnOApuE6y4Tg2iaibozGQZnia95ibFd3lnp8s32MU7Ny6FDZ4pyeeOOll9TrgEAKoTEQsgg/640?wx_fmt=png&from=appmsg "")  
  
如需POC，后台回复“脸通”即可  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK4JE3zBrw3XnOApuE6y4Tg2LgLzvuibXxqskFWQCOe1cXT5GEnEyiaKngFPRMQMbO8GnEcJaKv8pXXg/640?wx_fmt=png&from=appmsg "")  
  
  
