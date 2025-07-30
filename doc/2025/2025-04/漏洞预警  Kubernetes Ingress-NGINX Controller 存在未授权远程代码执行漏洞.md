#  漏洞预警 | Kubernetes Ingress-NGINX Controller 存在未授权远程代码执行漏洞   
原创 烽火台实验室  Beacon Tower Lab   2025-04-01 13:10  
  
**1**  
  
  
  
  
**漏洞概述**  
  
<table><tbody><tr style="box-sizing: border-box;"><td data-colwidth="30.0000%" width="30.0000%" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="text-align: center;box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;"><span leaf="">漏洞类型</span></strong></p></section></td><td data-colwidth="70.0000%" width="70.0000%" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="text-align: center;box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><span leaf="">远程代码执行</span></p></section></td></tr><tr style="box-sizing: border-box;"><td data-colwidth="30.0000%" width="30.0000%" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="text-align: center;box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;"><span leaf="">漏洞等级</span></strong></p></section></td><td data-colwidth="70.0000%" width="70.0000%" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="text-align: center;box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><span leaf="">高</span></p></section></td></tr><tr style="box-sizing: border-box;"><td data-colwidth="30.0000%" width="30.0000%" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="text-align: center;box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;"><span leaf="">漏洞编号</span></strong></p></section></td><td data-colwidth="70.0000%" width="70.0000%" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="text-align: center;box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><span leaf="">CVE-2025-1974</span></p></section></td></tr><tr style="box-sizing: border-box;"><td data-colwidth="30.0000%" width="30.0000%" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="text-align: center;box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;"><span leaf="">漏洞评分</span></strong></p></section></td><td data-colwidth="70.0000%" width="70.0000%" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="text-align: center;box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><span leaf="">9.8</span></p></section></td></tr><tr style="box-sizing: border-box;"><td data-colwidth="30.0000%" width="30.0000%" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="text-align: center;box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;"><span leaf="">利用复杂度</span></strong></p></section></td><td data-colwidth="70.0000%" width="70.0000%" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="text-align: center;box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><span leaf="">低</span></p></section></td></tr><tr style="box-sizing: border-box;"><td data-colwidth="30.0000%" width="30.0000%" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="text-align: center;box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;"><span leaf="">影响版本</span></strong></p></section></td><td data-colwidth="70.0000%" width="70.0000%" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="text-align: center;box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><span leaf="">Ingress-Nginx 在 v1.11.5、v1.12.1 之前的版本</span></p></section></td></tr><tr style="box-sizing: border-box;"><td data-colwidth="30.0000%" width="30.0000%" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="text-align: center;box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;"><span leaf="">利用方式</span></strong></p></section></td><td data-colwidth="70.0000%" width="70.0000%" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="text-align: center;box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><span leaf="">远程</span></p></section></td></tr><tr style="box-sizing: border-box;"><td data-colwidth="30.0000%" width="30.0000%" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="text-align: center;box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;"><span leaf="">POC/EXP</span></strong></p></section></td><td data-colwidth="70.0000%" width="70.0000%" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="text-align: center;box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><span leaf="">已公开</span></p></section></td></tr></tbody></table>  
  
  
近日，Ingress-Nginx 项目的维护者们发布了一批关键漏洞的修复补丁，其中包含了高风险漏洞（CVE-2025-29927），攻击者可以利用该漏洞轻易接管你的 Kubernetes 集群。目前有 40% 以上的 Kubernetes 管理员正在使用 ingress-nginx，建议您及时开展安全风险自查。  
  
  
Ingress-Nginx 是 Kubernetes 生态中基于 Nginx 实现的 ‌Ingress 控制器‌‌，用于管理集群外部的 HTTP(S) 和 WebSocket 流量路由‌。其核心作用是通过定义路由规则，将外部请求按域名、路径等策略转发至集群内部服务，并提供负载均衡、SSL 终止、限流等高级功能‌。  
  
  
据描述，Ingress-Nginx 在 v1.11.5、v1.12.1 之前的版本中存在一个安全漏洞。攻击者向同一 Pod 内的 NGINX 服务器发送一个长缓冲请求。NGINX 会将该请求缓存为一个临时文件，然后攻击者发送第二个请求至准入验证 Webhook 服务器（Admission Validating Webhook Server）。该 Webhook 会触发 NGINX 生成一个包含恶意配置指令 ssl_engine badso_location;准入 Webhook 会执行 nginx -t 命令来验证配置文件的合法性。由于 NGINX 在加载配置时会直接解析并执行特定指令，攻击者可通过恶意指令在 NGINX 服务器的上下文中触发远程代码执行（RCE），从而完全控制服务器。  
  
  
漏洞影响的产品和版本：  
  
< v1.11.0    
  
v1.11.0 - 1.11.4    
  
v1.12.0  
  
  
**2**  
  
  
  
  
**漏洞复现**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAOXuAnDbOcALtxreQeL0545yicxSQm39Uz0KyGOBFPylRNHImSuia9CkzdOyJsmE15svMtl8hShe9tw/640?wx_fmt=png&from=appmsg "")  
  
  
**3**  
  
  
  
  
**资产测绘**  
  
据daydaymap数据显示互联网存在15102个资产，国内风险资产分布情况如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAOXuAnDbOcALtxreQeL0545MooTxEt5dL1iaZy5ziamIaFic2mU3TfPv4iaicMzKEVNk3D9eM1C6mmV8eg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAOXuAnDbOcALtxreQeL0545qvva2DZKWNZvUU5WsBaNR8YgWiaLeiaicMSbYUXSKFiaQbiaKdr90DWyTwA/640?wx_fmt=png&from=appmsg "")  
  
  
**4**  
  
  
  
  
**解决方案**  
  
**临时缓解方案：**  
  
启用mTLS认证准入控制器；  
  
定期审计Ingress注解使用情况；  
  
实施Pod安全策略限制挂载敏感目录。  
  
**升级修复：**  
  
目前官方已发布修复安全补丁  
```
kubectl set image deployment/ingress-nginx-controller \controller=k8s.gcr.io/ingress-nginx/controller:v1.12.1
```  
  
  
**5**  
  
  
  
  
**参考链接**  
```
https://github.com/kubernetes/kubernetes/issues/131009
https://www.ddpoc.com/DVB-2023-9016.html
```  
  
  
  
  
  
  
