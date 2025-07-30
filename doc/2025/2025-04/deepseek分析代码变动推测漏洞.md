#  deepseek分析代码变动推测漏洞   
原创 进击的hack  进击的HACK   2025-04-18 23:51  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DuibU3GqmxVmRsdItbBVRKegNHicHQvAHDdZsGpLVU7touSU1AU1twHTfRjG3Vu5aUh0RnPPllfVUhs4qdWF5QYQ/640?wx_fmt=png&wxfrom=13 "")  
  
声明：  
文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途给予盈利等目的，否则后果自行承担！  
如有侵权烦请告知，我们会立即删除并致歉。谢谢  
！  
  
文章有疑问的，可以公众号发消息问我，或者留言。我每天都会看的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zYJrD2VibHmqgf4y9Bqh9nDynW5fHvgbgkSGAfRboFPuCGjVoC3qMl6wlFucsx3Y3jt4gibQgZ6LxpoozE0Tdow/640?wx_fmt=png&wxfrom=13 "")  
  
  
  
> 字数 447，阅读大约需 3 分钟  
  
## 前言  
  
日常刷公众号，看到了下面的内容：  
- • Alibaba Sentinel的SSRF[https://mp.weixin.qq.com/s/oWtP_BOYwHU7NvHkx229Pg](https://mp.weixin.qq.com/s?__biz=MzkzNzQyMDkxMQ==&mid=2247488015&idx=1&sn=545760ca33e14d7686d07b06618df721&scene=21#wechat_redirect)  
  
  
因为有issues，就点开github看了一下  
  
https://github.com/alibaba/Sentinel/commit/d4ea89e978d44a0991c41e410c6f5b073655b56b  
  
意外发现右边的三个点，点开有一个Ask about this diff  
  
![14dff7d794cf4452516d1bc88b92a72c.png](https://mmbiz.qpic.cn/sz_mmbiz_png/a1BOUvqnbrgc1x6x4yxaXDNGf9ewWURVSBu9ox3R8WZdiamg5miaib6cHCMXAfmcO9eUdyx8tHad0Scic8ICncDTPQ/640?from=appmsg "null")  
  
14dff7d794cf4452516d1bc88b92a72c.png  
  
这次更改在文件MachineRegistryController.java  
中引入了对 IP 地址合法性的进一步验证。  
## 更进一步  
  
既然github自带的可以，那么我们能不能把代码的diff内容发给deepseek之类的，分析一下更改前可能存在的安全问题，方便我们写poc和漏洞分析呢？  
  
说干就干。  
## git  
  
git clone 下载到本地  
```
git clone https://github.com/alibaba/Sentinel.git
```  
  
cd Sentinel  
```
git show d4ea89e978d44a0991c41e410c6f5b073655b56b
```  
  
结果  
```
diff --git a/sentinel-dashboard/src/main/java/com/alibaba/csp/sentinel/dashboard/controller/MachineRegistryController.java b/sentinel-dashboard/src/main/java/com/alibaba/csp/sentinel/dashboard/controller/MachineRegistryController.javaindex d11815d2..6552d1ce 100755--- a/sentinel-dashboard/src/main/java/com/alibaba/csp/sentinel/dashboard/controller/MachineRegistryController.java+++ b/sentinel-dashboard/src/main/java/com/alibaba/csp/sentinel/dashboard/controller/MachineRegistryController.java@@ -29,6 +29,7 @@ import org.springframework.stereotype.Controller; import org.springframework.web.bind.annotation.RequestMapping; import org.springframework.web.bind.annotation.RequestParam; import org.springframework.web.bind.annotation.ResponseBody;+import sun.net.util.IPAddressUtil; @Controller @RequestMapping(value = "/registry", produces = MediaType.APPLICATION_JSON_VALUE)@@ -51,6 +52,9 @@ public class MachineRegistryController {         if (StringUtil.isBlank(ip) || ip.length() > 128) {             return Result.ofFail(-1, "invalid ip: " + ip);         }+        if (!IPAddressUtil.isIPv4LiteralAddress(ip) && !IPAddressUtil.isIPv6LiteralAddress(ip)) {+            return Result.ofFail(-1, "invalid ip: " + ip);
```  
  
复制到大模型，提示词可参考下面的内容：  
```
作为网络安全专家，请分析本次代码提交的变更：1. 明确指出被添加安全限制的变量2.说明修复的具体安全漏洞类型（如：SQL注入/XSS/CSRF等）3.推测若无此修复，攻击者可能利用哪些恶意payload进行攻击4.如涉及特定漏洞，请解释其攻击原理变更代码块
```  
  
下面是大模型深度思考的结果  
  
![1896cc475ece0ad98f3781af8efc2071.png](https://mmbiz.qpic.cn/sz_mmbiz_png/a1BOUvqnbrgc1x6x4yxaXDNGf9ewWURVxubEErcP2REqYXibUVNVIcNvXeNPXzvGs9H5rggeuA3tQd2Zo8ibWgXg/640?from=appmsg "null")  
  
1896cc475ece0ad98f3781af8efc2071.png  
  
用的siliconflow：https://cloud.siliconflow.cn/i/5Zr8eFNI  
  
还没注册，想用的时候，可以用我上面的链接，给我添点  
  
![d2229abc042075b7068aeee6ef2768f0.png](https://mmbiz.qpic.cn/sz_mmbiz_png/a1BOUvqnbrgc1x6x4yxaXDNGf9ewWURVQ0q1uFgHUtKwMiaDz5zOIpBOStKn5RtNOOVn81YKdVr9qicprIyBdFmQ/640?from=appmsg "null")  
  
d2229abc042075b7068aeee6ef2768f0.png  
## 思考  
  
进一步扩展，监控某个项目，监听道道一次git commit，就将变更信息发送到大语言模型，分析是否存在安全风险，有的话，发送邮箱给你。  
  
  
  
  
  
