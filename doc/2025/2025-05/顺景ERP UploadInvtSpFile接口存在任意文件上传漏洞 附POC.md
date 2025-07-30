#  顺景ERP UploadInvtSpFile接口存在任意文件上传漏洞 附POC   
2025-5-13更新  南风漏洞复现文库   2025-05-13 15:18  
  
#   
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 顺景ERP简介  
  
微信公众号搜索：南风漏洞复现文库  
该文章 南风漏洞复现文库 公众号首发  
  
顺景ERP  
## 2.漏洞描述  
  
顺景ERP UploadInvtSpFile接口存在任意文件上传漏洞  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
顺景ERP  
![顺景ERP UploadInvtSpFile接口存在任意文件上传漏洞](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3ZjLXLia2Mf0X2MLSM0DQ9Msc51E68VNFFs1yHz7iaE2cS8uLLZZOSuXS3ylBPUPfL3aa41iaTr7EkUg/640?wx_fmt=png&from=appmsg "null")  
  
顺景ERP UploadInvtSpFile接口存在任意文件上传漏洞  
## 4.fofa查询语句  
  
body="/api/DBRecord/getDBRecords"  
## 5.漏洞复现  
  
漏洞数据包：  
  
上传成功会返回路径  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZjLXLia2Mf0X2MLSM0DQ9MsibdYqcp2rA8lbTP0laeCNCqpvE6hJrJdZW5Nu1CLFJialJaVSI1gQdyg/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
拼接路径即可访问上传的文件  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZjLXLia2Mf0X2MLSM0DQ9MspNlVp2oyWl9JYzicnJHXtkdbW27nB5mYL4xHYicJTTicxkhxTGjqkDQRw/640?wx_fmt=jpeg&from=appmsg "null")  
  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全  
1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。  
2: 免登录，免费fofa查询。  
3: 更新其他实用网络安全工具项目。  
4: 免费指纹识别，持续更新指纹库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZjLXLia2Mf0X2MLSM0DQ9MsqjoDKMoralHmk41VnChdic6OuCvk7ArnMrgYCVnTUoV4tvc8rXUIA5g/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZjLXLia2Mf0X2MLSM0DQ9MsQekTQia3us5GFePWNwffpVDnmx68nWNEibibY697SZ1w7AR3ZaDXKYPMw/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZjLXLia2Mf0X2MLSM0DQ9Ms1EW7wTsqgx2OvD2UlMAdicJkN3CAcCHUxpFibejq5QIOF0DD4QibUbTow/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZjLXLia2Mf0X2MLSM0DQ9MstJNRw544nvibZwlcYtGQDTpu8VNr3ibU28aLBtnhM7LFia2s6Q3hrx5Rw/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZjLXLia2Mf0X2MLSM0DQ9MsH9D62qibPJpjqR9pXYN4icVjaPT1hYfIBevFGoLmh67KXYicpIVM54pjA/640?wx_fmt=jpeg&from=appmsg "null")  
  
## 7.整改意见  
  
打补丁  
## 8.往期回顾  
  
  
   
  
  
  
