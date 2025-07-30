#  【漏洞预警】Kubernetes Windows命令注入漏洞   
cexlife  飓风网络安全   2025-03-14 22:55  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu00S0lCUKy9ibobSm2kYSJicPACp8FKl0RwhKJEn1LrxbPw0CmB2IR90BdBibMpF2F25GgQq2icl1VPPsw/640?wx_fmt=png&from=appmsg "")  
  
漏洞描述:  
  
Kubеrnеtеѕ Windоԝѕ节点中存在个安全漏洞,该漏洞可能允许具有高权限用户查询节点的/lоɡѕ端点以在主机上执行任意命令。   
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu00S0lCUKy9ibobSm2kYSJicPAE0bKWYGE4R13wpoiachiaxnJVjnI3sPmCpzX7QRnl43hzVicy0ff6TqsA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu00S0lCUKy9ibobSm2kYSJicPAPEJBme4u3TfGeN2a9ofGnEYQk98muEg2Isc3mQ4tkwW8uP4pZ8182A/640?wx_fmt=png&from=appmsg "")  
  
影响产品:  
  
1、 Kubernetes v1.32.0  
  
2、 v1.31.0 <=Kubernetes <= v1.31.4  
  
3、 v1.30.0 <=Kubernetes <= v1.30.8  
  
4、 Kubernetes <=v1.29.12   
  
修复建议:  
  
补丁名称:  
  
Kubеrnеtеѕ Windоԝѕ命令注入漏洞的补丁—更新至最新版本1.32.3  
  
公告链接：  
  
https://github.com/advisories/GHSA-vv39-3w5q-974q  
  
文件链接：  
  
https://github.com/kubernetes/kubernetes/releases/tag/v1.32.3   
  
目前官方已有可更新版本,建议受影响用户升级至最新版本   
  
参考链接:  
  
https://www.openwall.com/lists/oss-security/2025/01/16/1  
  
  
