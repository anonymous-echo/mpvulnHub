#  瑞友天翼应用虚拟化系统RAPAgent.XGI接口存在SQL注入漏洞 附POC   
2025-2-27更新  南风漏洞复现文库   2025-02-27 14:57  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 瑞友天翼应用虚拟化系统简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
瑞友天翼应用虚拟化系统是具有自主知识产权，基于服务器计算（Server-based Computing）架构的应用虚拟化平台。  
## 2.漏洞描述  
  
瑞友天翼应用虚拟化系统是西安瑞友信息技术资讯有限公司研发的具有自主知识产权，基于服务器计算（Server-based Computing）架构的应用虚拟化平台。瑞友天翼应用虚拟化系统RAPAgent.XGI接口存在SQL注入漏洞，攻击者可以利用此漏洞获得数据库和WEB主机权限。  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
瑞友天翼应用虚拟化系统  
  
![瑞友天翼应用虚拟化系统RAPAgent.XGI接口存在SQL注入漏洞](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3Zhv6uHHYeZuRLRiaJwBRE9k6N8bWUtF3NOEVWhrEmKKmcwRUCvwawPvaQFWchuYFLiamanSV74wDWA/640?wx_fmt=png&from=appmsg "null")  
  
瑞友天翼应用虚拟化系统RAPAgent.XGI接口存在SQL注入漏洞  
## 4.fofa查询语句  
  
app="REALOR-天翼应用虚拟化系统"  
## 5.漏洞复现  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Zhv6uHHYeZuRLRiaJwBRE9kFFc3vMtKTGLu8pDQuLB1icSicomWGLn9y4YW6h1plic65vKR9hXlhP7ZA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Zhv6uHHYeZuRLRiaJwBRE9kwmCY0lrMe1qxr8RhGPc4Meh9kSWKZz8v24Zj8sRb6fDXp9zFXMDBsg/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全  
1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。  
2: 免登录，免费fofa查询。  
3: 更新其他实用网络安全工具项目。  
4: 免费指纹识别，持续更新指纹库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Zhv6uHHYeZuRLRiaJwBRE9kZnEPX3Wq7gC1qoJMky7DeuWUYOFCMKogAKXicRticdDGft6K9KDREDibw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Zhv6uHHYeZuRLRiaJwBRE9kc6M35ScOo8thwugncRGIbiaNYXMaP9l6m7ibTKfYQRgS6xgObU6Ar1RA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Zhv6uHHYeZuRLRiaJwBRE9kKPnwYjEWSdjXicuWwJhlGZeHic266kh9jlF2KvUTB8HNNWp9oCX5lXYA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Zhv6uHHYeZuRLRiaJwBRE9kSzWV2HtI4LueEwkGsTBF4AomLmroptJ1snzrHWQw3slQLSjkUGanLA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Zhv6uHHYeZuRLRiaJwBRE9kHeM1xlTFJUgf0chMtMFMfhtibccRAKhBz8iaIYGtL1OczpyEP7J2jQpg/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
厂商尚未提供漏洞修补方案，请关注厂商主页及时更新： http://www.realor.cn  
## 8.往期回顾  
  
  
  
