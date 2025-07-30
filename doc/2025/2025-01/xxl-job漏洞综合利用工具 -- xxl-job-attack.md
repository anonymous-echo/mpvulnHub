#  xxl-job漏洞综合利用工具 -- xxl-job-attack   
pureqh  Web安全工具库   2025-01-29 16:00  
  
===================================  
免责声明请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。个人微信：ivu123ivu  
0x01 工具介绍  
xxl-job漏洞综合利用工具。  
```
1、默认口令
2、api接口未授权Hessian反序列化
3、Executor未授权命令执行
4、默认accessToken身份绕过
```  
  
0x02 安装与使用  
运行界面  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibtGRUTyueJRuvPPUOK5EaSF5bgCoZ4ibqvtlMJrcaga7ibuD6mLdGTSIbkMTYzx0VTXiasMOQa0I9GVw/640?wx_fmt=png&from=appmsg "")  
  
关于内存马  
  
1、内存马使用了xslt，由于测试直接打入内存马有时会失败，所以选择直接打入agent内存马  
  
2、如需自定义可替换resources下的ser文件，其中agent.ser为agent内存马、xslt.ser会落地为/tmp/2.xslt  
  
3、内容为使用exec执行/tmp/agent.jar、exp.ser则是加载/tmp/2.xslt  
  
4、默认注入vagent内存马，连接信息冰蝎:http://ip:port/xxl-job-admin/api/luckydayb,其他类型内存马类似， 将favicon改为luckyday即可  
  
5、由于agent发送文件较大，所以可能导致包发不过去，建议多试几次或者将超时时间延长  
  
6、由于Hessian反序列化基本上都是直接发二进制包，所以理论上讲其他的Hessian反序列化漏洞也可以打  
  
  
  
**·****今 日 推 荐**  
**·**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3Uibt8HicPVj697RP3iacXJibQGDkCf2CLHOrPvcULHYbrqzx49vUXiaIkfW6wfFjlBeDz1icIUHkvCgic4kgg/640?wx_fmt=png "")  
  
