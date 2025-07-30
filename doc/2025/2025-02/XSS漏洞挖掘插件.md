#  XSS漏洞挖掘插件   
 黑白之道   2025-02-08 06:09  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
## 工具介绍  
  
对<a herf标签和form表单中的参数进行遍历  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2Wbia99suJTwSxpyFnhHiaDiczuvvud5jTjmj3Yz5jIm9SFD3h3ySPgNzcUNSLTB9WicjTCycCg95rNlg/640?wx_fmt=png&from=appmsg&wxfrom=13&tp=wxpic "")  
## 功能特性  
- 根据自己提供的xsspayload进行批量测试，默认使用的是<img src=x onerror=alert(1)>  
  
- 分析页面可以利用的参数：有action属性的form表单，a标签herf属性值  
  
## 安装使用  
1. **安装插件**：将插件**文件夹**托到浏览器的扩展程序中就ok了(目前只支持chrome内核的浏览器)。  
  
1. **使用插件**：点击浏览器工具栏中的插件图标，输入自定义payload。  
  
1. **查看结果**：扫描完成后，插件会在弹出窗口中显示检测结果，标明发现的敏感参数。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2Wbia99suJTwSxpyFnhHiaDiczibtVAylaoOw9OnTXataSVibSzvYNupaNXXW1qickuSDg58U4LUwCAcxsg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
## 工具获取  
  
  
  
https://github.com/Yn8rt/Jssx/tree/master  
  
> **文章来源：夜组安全**  
  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  
