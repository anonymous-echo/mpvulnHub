#  攻防实战绕过disable_function命令执行   
原创 ashui  Rot5pider安全团队   2025-04-25 02:59  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1K26bQox3P7WP9dbZ8fiaWVicOSxjNfqYduiciaQ0iaZ7WFyadLnzbVicK8tW7YU4UEib2EsP5twVZ7IH4Yw/640?wx_fmt=png&from=appmsg "")  
  
  
蓝  
  
队  
  
         
  
# 蓝队短期HVV攻防演练项目招聘（北京）  
  
**工作内容：**  
  
负责前期渗透测试及HVV（攻防演练）期间的安全研判、不需要应急。  
  
**项目周期：**  
2个月（含前期渗透准备阶段及HVV实战阶段），五一后启动，具体入场时间面试通过后通知。  
  
**工作地点：**  
北京  
  
**薪资待遇：**  
税前月薪 1.5万-2.2万，面议合格后会发薪资价格； 薪资年底结算。入场可提前垫付10%-20%  
  
**任职要求：**  
熟悉渗透测试流程，具备Web渗透经验； 有HVV项目经验者优先； **责任心强，能适应高强度任务，具备团队协作能力。  
  
**投递方式：**  
** 请将简历发送至380622021@qq.com，邮件标题注明【姓名+号码】，通过面试后会联系通知。  
  
**注：年底包结款，能扛得住的兄弟来。**  
  
    
  
  
#   
## 一、目标资产发现  
### 1.1 资产定位  
  
源于某运营商的攻防，仅用于记录与学习交流，大佬轻喷 在庞大的资产中找到一个边缘的小程序，经简单测试后，发现在头像上传处使用的白名单校验，本以为整个小程序都是使用同一上传接口。结果发现另外一个上传点和头像上传处的接口不一致，且可以上传php后缀  
- 在运营商大型资产池中发现孤立小程序节点  
  
- 初始误判：通过头像上传功能推测统一上传接口  
  
- 突破点：发现独立上传接口/upload.php  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1Jp0sKd9CWCVqyJpNEk98Q174USwtap1ibmm5JHicneqxibbHSsWD25iayyXwU56x0oyOJdiagDm24DSNg/640?wx_fmt=png&from=appmsg "")  
先echo个hello world能否解析，成功了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1Jp0sKd9CWCVqyJpNEk98Q1YLBzgAjwOf2gWkibmOlSmiaL9RwoMm211vtK7uOicEPaWzDJIiapOQhM2w/640?wx_fmt=png&from=appmsg "")  
上传个一句话木马，响应包空白(忘记截图了) 多次尝试后，使用免杀php马成功上传![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1Jp0sKd9CWCVqyJpNEk98Q1L5hh6qhsDs78n9VOOqhuUe5T0fiaZ8qfFcyFSrFLOKEZc01P8XrcVlg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1Jp0sKd9CWCVqyJpNEk98Q1AnFoM9tGmWCCARzqVcTrx6BPS0htP3Fr8ibhNEv1qRlNatlUYj1OfFQ/640?wx_fmt=png&from=appmsg "")  
当尝试命令执行时，发现命令都是这个回显，这说明受到disable_function的限制![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1Jp0sKd9CWCVqyJpNEk98Q1eVtn3Nhue3kbeGV6IiaB6ZMrRbiaS5d3VeNGYdRcQxjgfJHfKsAWBFrw/640?wx_fmt=png&from=appmsg "")  
可以使用蚁剑的插件进行绕过，笔者这里使用哥斯拉 可直接绕过限制命令执行![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1Jp0sKd9CWCVqyJpNEk98Q19WYlK43iceZvlNhC2JRWib2An3loibfyDibQejNXvhiaW5cuk71zCRAKbRQ/640?wx_fmt=png&from=appmsg "")  
后续就是上线vshell、简单看了下，没什么防护，毕竟是边缘资产 挂代理，直接fscan扫，可惜这个内网比较小 后续就拿了一些ftp、数据库和web管理员的权限![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1Jp0sKd9CWCVqyJpNEk98Q1Ng4VMPIKoXeR7XMmFDoDI2eEasXm0yibefIgWWMZkQTsJ2BhHN50UJA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1Jp0sKd9CWCVqyJpNEk98Q1544tGSR4IBOUfKAJnJ4KAUrPuBJt8ibXd3Rsic0Wicf4icJgg5TJyv5tqw/640?wx_fmt=png&from=appmsg "")  
从数据库中翻到web页面的管理员用户密码![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1Jp0sKd9CWCVqyJpNEk98Q19CElqAL6eaAlGQ8F9HKKrmUE0kwd2Lmuunla0RGHAECTonW2JZfeAQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1Jp0sKd9CWCVqyJpNEk98Q1gNibyIe4AmU5a5KPw5Dt3hjNgkiaZlJyUNEkibOGic6bk2CqeD1kmbRQ6g/640?wx_fmt=png&from=appmsg "")  
### 1.2 技术验证  
```
POST /upload.php HTTP/1.1
Host: edge.xxxx.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="test.php"
Content-Type: application/octet-stream

<?php echo "Hello World"; ?>
------WebKitFormBoundary--

```  
- 响应包验证：  
  
```
HTTP/1.1 200 OK
Content-Length: 12

Hello World!

```  
## 二、漏洞利用链  
### 2.1 文件上传突破  
  
<table><thead><tr><th style="color: rgb(0, 0, 0);font-size: 16px;line-height: 1.5em;letter-spacing: 0em;text-align: left;font-weight: bold;background: rgb(240, 240, 240) left top no-repeat;height: auto;border-style: solid;border-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;padding: 5px 10px;min-width: 85px;"><section><span leaf="">接口</span></section></th><th style="color: rgb(0, 0, 0);font-size: 16px;line-height: 1.5em;letter-spacing: 0em;text-align: left;font-weight: bold;background: rgb(240, 240, 240) left top no-repeat;height: auto;border-style: solid;border-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;padding: 5px 10px;min-width: 85px;"><section><span leaf="">允许后缀</span></section></th><th style="color: rgb(0, 0, 0);font-size: 16px;line-height: 1.5em;letter-spacing: 0em;text-align: left;font-weight: bold;background: rgb(240, 240, 240) left top no-repeat;height: auto;border-style: solid;border-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;padding: 5px 10px;min-width: 85px;"><section><span leaf="">绕过方法</span></section></th></tr></thead><tbody><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: left;background-position-y: top;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">头像接口</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">jpg/png</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">MIME类型欺骗</span></section></td></tr><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: left;background-position-y: top;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">独立接口</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">php</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">.htaccess重写规则</span></section></td></tr></tbody></table>  
### 2.2 Webshell部署  
- 使用哥斯拉免杀马（AES加密+动态混淆）  
  
- 上传路径：/data/avatar/2025/02/01/tmp_167890.php  
  
- 特征隐藏：通过preg_replace  
动态生成木马主体  
  
## 三、权限提升  
### 3.1 环境限制  
- 禁用函数检测：  
  
```
disable_functions=system,passthru,exec,shell_exec,popen,proc_open,pcntl_exec

```  
### 3.2 绕过技术  
- 使用哥斯拉LD_PRELOAD  
绕过插件  
  
- 执行链路：  
  
```
LD_PRELOAD=/tmp/libhide.so /usr/bin/php-cgi -f /path/to/malicious_script.php

```  
## 四、横向移动  
### 4.1 内网探测  
- 使用Fscan快速扫描：  
  
```
fscan -h 192.168.1.0/24 -p 22,3306,6379 --threads 50

```  
- 发现低防护FTP/MySQL服务  
  
### 4.2 凭证获取  
- 从数据库备份文件恢复管理员凭证：  
  
```
SELECT user, password_hash FROM admin_credentials LIMIT 1;

```  
- 使用hashcat破解：  
  
```
hashcat -m 3200 hash.txt rockyou.txt --force

```  
## 五、防御突破总结  
### 5.1 关键突破点  
1. 多接口资产图谱缺失导致防御盲区  
  
1. .htaccess动态配置管理缺陷  
  
1. 禁用函数绕过机制不完善  
  
### 5.2 安全加固建议  
```
graph TD
    A[资产管理] --> B{资产发现}
    B --> C[流量+主动扫描]
    B --> D[暗网监控]
    C --> E[端口协议分析]
    D --> F[情报关联]

```  
- 建议部署：  
  
- 文件完整性监控（Wazuh）  
  
- 动态沙箱分析（Cuckoo Sandbox）  
  
- RASP运行时防护  
  
  
  
  
  
【限时  
6  
折！华普安全研究星球：以  
原创实战  
为主+SRC/内网渗透核心资源库，助你在漏洞挖掘、SRC挖掘少走90%弯路】当90%的网络安全学习者还在重复刷题、泡论坛找零散资料时，华普安全研究星球已构建起完整的「攻防实战知识生态」：  
  
✅ 原创深度技术文档（独家SRC漏洞报告/代码审计报告）  
  
✅ 实战中使用到的工具分享  
  
✅ 全年更新SRC挖掘、代码审计报告（含最新0day验证思路）  
  
✅ 漏洞挖掘思维导图  
  
✅内部知识库、入圈子免费进入  
  
【  
实战为王  
】不同于传统课程的纸上谈兵！！  
  
内容每日更新  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1Jp0sKd9CWCVqyJpNEk98Q1fUnAJaQsMjraqQATTKNOrhG32SR7Dc1kjBSHM4lwysXTrRNeq2DvWA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1Jp0sKd9CWCVqyJpNEk98Q185oUMA7wIeGmblA59HZ8gOLGbXxYKfcjKiaOsQ029Iiag9PFubcHE4xA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1Jp0sKd9CWCVqyJpNEk98Q1f2XVF7F5WJNW2tAPSlpI5Eo1GQWicdbvkhamuhcATTBe2mKePBOW5GA/640?wx_fmt=png&from=appmsg "")  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KibZGSTtYYMVNzA35ZxXVRT1s5WIQzLQXibdxCf6fkianYH5bSeKhcPcQPNR8E1iaJz2aAqonzogTKicg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KibZGSTtYYMVNzA35ZxXVRTxJibeicaQ0uttmutBuckibQFCEVicpyhhWXprQVOn4AnAnpDauQiaWTblMQ/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1Jp0sKd9CWCVqyJpNEk98Q12WFEV9ajufAFCLG2zYZxiaVxp2UvxEqd7CTPCcUbL2YLFY5P4el3hsw/640?wx_fmt=png&from=appmsg "")  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/OMTnCvx3T1KibZGSTtYYMVNzA35ZxXVRT7UqeH8ibia1N77Q9iaLtwD9NU7Nt9gicr8sdmDGfQQvibnTDKQYNIJP6tFw/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
  
**后期我们将持续发布原创代码审计、src等漏洞挖掘文章，后期有些源码、挖掘思路等也会放进圈子哈~**  
  
**有任何问题可后台留言**  
  
  
  
  
往期精选  
  
  
  
围观  
  
[PHP代码审计学习](http://mp.weixin.qq.com/s?__biz=Mzg5OTYxMjk0Mw==&mid=2247484594&idx=1&sn=89c96ed25e1f1d146fa3e67026ae0ca1&chksm=c051ecd2f72665c45d3e8c51b94629319b992f7f459d5677d7ce253eac99fc5e2e8f78684907&scene=21#wechat_redirect)  
  
  
丨更多  
  
热文  
  
[浅谈应急响应](http://mp.weixin.qq.com/s?__biz=Mzg5OTYxMjk0Mw==&mid=2247484589&idx=1&sn=80ff6dbb4471c101a71e203a10354d59&chksm=c051eccdf72665db0530fce6a332bf44392fb0c4d3d61496c9141bb93ece816cbbe97f89d06f&scene=21#wechat_redirect)  
  
  
丨更多  
  
·end·  
  
—如果喜欢，快分享给你的朋友们吧—  
  
我们一起愉快的玩耍吧  
  
  
  
【免责声明】  
  
"Rot5pider安全团队"作为专注于信息安全技术研究的自媒体平台，致力于传播网络安全领域的前沿知识与防御技术。本平台所载文章、工具及案例均用于合法合规的技术研讨与安全防护演练，严禁任何形式的非法入侵、数据窃取等危害网络安全的行为。所有技术文档仅代表作者研究过程中的技术观察，不构成实际操作建议，更不作为任何法律行为的背书。  
  
  
  
  
  
  
  
