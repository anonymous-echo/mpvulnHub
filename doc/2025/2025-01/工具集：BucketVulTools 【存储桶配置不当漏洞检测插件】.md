#  工具集：BucketVulTools 【存储桶配置不当漏洞检测插件】   
wolven Chan  风铃Sec   2025-01-21 04:18  
  
### 工具介绍  
  
Burpsuite存储桶配置不当漏洞检测插件，目前支持阿里云，华为云，腾讯三个厂商的检测，存储桶文件遍历，acl读写，Policy读写及未授权上传。  
### 用法  
  
存储桶相关配置检测自动化，访问目标网站将会自动检测，如：访问的网站引用存储桶上的静态资源，就会触发检测逻辑,将指纹识别方式修改了下，通过server头及域名中的一个方式进行判断，另外由于敏感信息误报较多，已经取消了。  
  
将插件导入Burpsuite  
  
**检测结果**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qGTEdaLg0HnYFaRurC2tho6aicNJfnYKFo5HDVVpDwkRW3k0zwibFLGzjVjRyKK6Yln8TgobcHkqzR5w2uribqibZQ/640?wx_fmt=png&from=appmsg "")  
  
**使用的新版bp接口，所以版本有要求，jdk17**  
#### 项目地址  
```
```  
  
