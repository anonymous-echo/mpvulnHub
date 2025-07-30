#  Burpsuite存储桶配置不当漏洞检测插件   
 黑白之道   2025-02-02 02:16  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
**01**  
  
**工具介绍**  
  
存储桶相关配置检测自动化，访问目标网站将会自动检测，如：访问的网站引用存储桶上的静态资源，就会触发检测逻辑,将指纹识别方式修改了下，通过server头及域名中的一个方式进行判断，另外由于敏感信息误报较多，已经取消了。  
## 导入burpsuite  
## 存储桶相关配置问题检测结果同步到bp的issue  
## 检测结果，目前支持阿里云，华为云，腾讯三个厂商的检测，存储桶文件遍历，acl读写，Policy读写及未授权上传  
  
 ![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2XUsVf0BYHK9lBfjbr5JjHXEw6vxTHzQ4IpQmEf1AyAst0a2QTMe5ZG7E9BIwElrUY6VUA7dPHnTQ/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
使用的新版bp接口，所以版本有要求，jdk17  
## 打包  
```
mvn package
```  
## 导入bp  
##   
## 敏感字段会在这个面板展示  
##   
  
  
**02**  
  
**工具下载**  
  
****https://github.com/libaibaia/BucketVulTools****  
  
> **文章来源：夜组安全**  
  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  
