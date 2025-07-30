#  DockerUI存在默认口令漏洞，可导致拉取镜像，管理等操作   
原创 Mstir  星悦安全   2024-12-09 04:40  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们 并设为  
星标  
## 0x00 前言  
  
**DockerUI是一款开源的、强大的、轻量级的Docker管理工具。DockerUI覆盖了 docker cli 命令行 95% 以上的命令功能，通过可视化的界面，即使是不熟悉docker命令的用户也可以非常方便的进行Docker和Docker Swarm集群进行管理和维护。**  
  
**Fofa指纹:"static/common/js/ui.js"**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ew9KxZowGzw1pf3FAooqFzR2icMxHwPNslmfoHpxPyYIrdKDjfUjicpvH4oJYJue1pDKl2sm1CEr0w/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ew9KxZowGzw1pf3FAooqFzsQGUqtH4fAhYYUo8SicUHdBIsic8f8AqicgdJbbC3c35uPWFbVh05QVfg/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ew9KxZowGzw1pf3FAooqFzNsTySxuiaYJcvd4jUTYzl0VFLic06X0C8Fe4miaLqG7BAZ2Alg6gkczBg/640?wx_fmt=png&from=appmsg "")  
## 0x01 漏洞分析&复现  
  
**DockerUI搭建完成默认口令为:ginghan/123456**  
  
**进入后台后可直接可以拉取镜像，管理容器和网络环境**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ew9KxZowGzw1pf3FAooqFztUGsklJ8x6aicMgfEicOx3MSzehARmnKhAo04loVedHjJMl0nE6EBCXw/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ew9KxZowGzw1pf3FAooqFzIic9OocCd7fLg4OE1qzCAHTuMljmf26TOQhRdlBQGNfqdu90Nktlhdw/640?wx_fmt=png&from=appmsg "")  
## 0x02 源码下载  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转**  
  
**DockerUI源码关注公众号发送 241209 获取!**  
  
  
  
  
下方二维  
码添加好友，回复关键词   
**星悦安全**  
进群  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8CGA5xDtuNnCSVGd0ibW86zZaJ6tr5ib17xnMbupUibq24HQEl4gRoptsVgCBSNnwBEGmSn3a4ftXVzQ/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8AOzYX7kxefGbGGZg3g1ltkN30q9hceg23PiczgUqMT0EE9w0fLK9uw1eKWwQX9TljXQe1OQeHRZ2Q/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
**免责声明:****文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
