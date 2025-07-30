#  快讯丨工信部：关于防范Apache Struts2任意文件上传超危漏洞的风险提示   
 工业安全产业联盟平台   2025-01-06 10:56  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/4FpQm8QaW5lbFib0cYqFJ8oRVrcgU8sQRFvEn4dPWUM37N5AGvOKUfvgiaDbX7ziciatXMvchxaqp7icoqiaUEicpImTw/640?wx_fmt=gif&from=appmsg "")  
  
  
  
  
  
近日，工业和信息化部网络安全威胁和漏洞信息共享平台（NVDB）监测发现，开源应用框架Apache Struts2存在任意文件上传超危漏洞，可被恶意利用实现远程代码执行，导致敏感数据泄露和系统受控。  
  
  
Apache Struts2是一款开源Java Web应用程序开发框架，广泛用于构建企业级Web应用程序。因该框架中FileUploadInterceptor组件存在逻辑缺陷，攻击者可利用文件上传构造恶意请求，通过操纵文件上传参数执行路径遍历，将恶意文件上传至其他目录，实现远程代码执行。受影响版本包括：2.0.0≤ver≤2.3.37、2.5.0≤ver≤2.5.33、6.0.0≤ver≤6.3.0.2。目前，Apache基金会官方已修复该漏洞并发布安全公告（URL链接：https://cwiki.apache.org/confluence/display/WW/S2-067）。  
  
  
建议相关单位和用户立即开展全面排查，按照官方安全公告升级至6.4.0或更高版本，并使用ActionFileUploadInterceptor作为文件上传组件，或采取禁用FileUploadInterceptor、添加上传文件类型白名单、加强系统和网络的访问控制等安全防护措施，防范网络攻击风险。  
  
  
感谢北京启明星辰信息安全技术有限公司、北京微步在线科技有限公司、北京神州绿盟科技有限公司、北京天融信网络安全技术有限公司、深信服科技股份有限公司、北京长亭科技有限公司、奇安信网神信息技术（北京）股份有限公司等提供技术支持。  
  
  
  
**· end ·**  
  
  
来源 | 网络安全威胁和漏洞信息共享平台  
  
责任编辑 | 赫敏  
  
  
声明：本文由工业安全产业联盟平台微信公众号（微信号：ICSISIA）转发，如有版权问题，请联系删除。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/4FpQm8QaW5kiaicHTUwSf9sId0er1ytR3D1Sc1RPfDpmk8FiciciadlBic9jSUbt1ciaE3G3aKiaicickE5ficq81KuYplgow/640?wx_fmt=png "")  
  
  
  
**如需合作或咨询，请联系工业安全产业联盟平台小秘书微信号：ICSISIA20140417**  
  
  
  
**往期荐读**  
  
[荐读 | 工业嵌入式控制系统可信计算技术应用研究](http://mp.weixin.qq.com/s?__biz=MzI2MDk2NDA0OA==&mid=2247519333&idx=2&sn=bf43af3fddbb39488cd710e74a1032ed&chksm=ea6367dadd14eeccb05e00991d2102691823321dc5ab0cec7cdbf0b7fdbababcf3072ef9bab5&scene=21#wechat_redirect)  
  
  
[重磅 | 《自动化博览》2024年第一期暨《工业控制系统信息安全专刊（第十辑）》上线](http://mp.weixin.qq.com/s?__biz=MzI2MDk2NDA0OA==&mid=2247526449&idx=1&sn=8833fa51b2d2d561b92a903afe7d3940&chksm=ea63838edd140a987d94f7154fd7e61808299215c930bec12eb4d1349dc8f642e21ddd055ea5&scene=21#wechat_redirect)  
  
  
[解决方案 | 长输供热工程工控安全防护解决方案](http://mp.weixin.qq.com/s?__biz=MzI2MDk2NDA0OA==&mid=2247519250&idx=1&sn=ef38b08e844bd87ea31f7c255749a2d2&chksm=ea6367addd14eebbad577732f522bae728f9b27f4f5f8924ce494af774ce7bd0637578052a47&scene=21#wechat_redirect)  
  
  
[关注 | 两会话安全：网络安全提案速览](http://mp.weixin.qq.com/s?__biz=MzI2MDk2NDA0OA==&mid=2247519102&idx=1&sn=82cc167aa7b73ea80a8306b1a0628cfc&chksm=ea6360c1dd14e9d7bb308b186182d17336c154fe084eee541ceb75b39edae090bc4fa7d6a936&scene=21#wechat_redirect)  
  
  
[荐读 | 工业互联网渗透测试技术研究](http://mp.weixin.qq.com/s?__biz=MzI2MDk2NDA0OA==&mid=2247519019&idx=1&sn=77752855e976481fa468f1771f943d9f&chksm=ea636094dd14e98212426441e59d8b26bf4739a9099ae2f0e95dc5849889fe5de2420115afe3&scene=21#wechat_redirect)  
  
  
[解决方案 | 精细化工产业互联网安全体系建设方案](http://mp.weixin.qq.com/s?__biz=MzI2MDk2NDA0OA==&mid=2247519524&idx=1&sn=9cfea10f776336d016f54b398bd49d13&chksm=ea63669bdd14ef8d331333ae32ca7470321b566adb26c8559d4614c694e85553477318fa88b1&scene=21#wechat_redirect)  
  
  
[荐读 | 智能制造装备安全方案](http://mp.weixin.qq.com/s?__biz=MzI2MDk2NDA0OA==&mid=2247519506&idx=1&sn=56c9d0355d2c8b769ad8eb3c046d64fc&chksm=ea6366addd14efbb0741053e462cb5c029b4cccc3dc886ffa1cfdf630aa400248315c44cb0d8&scene=21#wechat_redirect)  
  
  
[观点 | CCF计算机安全专委会发布2023年网络安全十大发展趋势](http://mp.weixin.qq.com/s?__biz=MzI2MDk2NDA0OA==&mid=2247518554&idx=1&sn=e2a24ea69c914133583f0b2361417af1&chksm=ea6362e5dd14ebf33f035330815cba14b344f2100799e1c8e4d46ee74fc7afd0f39d9e520641&scene=21#wechat_redirect)  
  
  
[荐读 | 智能制造背景下我国工业网络安全的新挑战](http://mp.weixin.qq.com/s?__biz=MzI2MDk2NDA0OA==&mid=2247519439&idx=1&sn=51637c6f276e86baa666b5812ef3bb03&chksm=ea636770dd14ee66da717009491d91283c666a7f755ff45bd49c6d1eff4b41ec29210ef0de66&scene=21#wechat_redirect)  
  
  
[报告 | 《中国网络安全产业研究报告》发布：多方利好驱动网络安全产业高质量发展](http://mp.weixin.qq.com/s?__biz=MzI2MDk2NDA0OA==&mid=2247518760&idx=1&sn=ded3f64e6fd6418f61be5a9287c20264&chksm=ea636197dd14e881a65fa9de6fb17a5490933c41879be32d043bb1c0aba9a2a6f310e16a83b0&scene=21#wechat_redirect)  
  
  
[荐读 | 基于改进预处理PCA算法的代码混淆分析](http://mp.weixin.qq.com/s?__biz=MzI2MDk2NDA0OA==&mid=2247519239&idx=1&sn=e91df29cbcf48862f57011ba38a10a3f&chksm=ea6367b8dd14eeaedd9ce58fe699e16f3dbba2aea71bf63c34df5a1ce15dd8513075bfb80fcb&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/4FpQm8QaW5kl2a8G7lfZTXQ65jPLzCdpyKsyPqcbQnzEqbmYSDib90bZicWWGDc7kFPbaRiaVzC16MXUp4T0FY8cA/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FpQm8QaW5kl2a8G7lfZTXQ65jPLzCdpMs8tAvMDjxib9jwveZic6lrGG8K5iaoRIibBzbMEOZ1iay9MmF0aJtvicHmQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/4FpQm8QaW5kl2a8G7lfZTXQ65jPLzCdpQrnsLdgPsjvdBHkvnibporOYKicPv4aBgHkEw0tLgNnDuOTOOAia2tPug/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/4FpQm8QaW5kl2a8G7lfZTXQ65jPLzCdpgJgfShwDlZNGBxX5EkH8XMYawAfotAVmiaoD9icCOE7l306nqjCsuibCw/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/4FpQm8QaW5kl2a8G7lfZTXQ65jPLzCdp1IQNNBb9Hm4vRAiaKFBY2gMMDZB2IBvpkaCEetNoQvPFnwv2Tb13PuA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
