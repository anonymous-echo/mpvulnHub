#  CNNVD | 关于OpenSSH安全漏洞的通报   
 中国信息安全   2024-07-03 18:41  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1brjUjbpg5wCKFntVibTsmfnGHWYwhZnebWmPLEEJZ4ib8z7icPTKIFibd806bhekHLLe4ickOX6nssakpCuV25J05Q/640?wx_fmt=gif&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1brjUjbpg5wCKFntVibTsmfnGHWYwhZneehCQbg0wz6hiboibYzVyAJ0QFh3eeVfUz52nzM18xict6UEZMXI1GyvrA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1brjUjbpg5wCKFntVibTsmfnGHWYwhZnebWmPLEEJZ4ib8z7icPTKIFibd806bhekHLLe4ickOX6nssakpCuV25J05Q/640?wx_fmt=gif&from=appmsg "")  
  
**扫码订阅《中国信息安全》**  
  
  
邮发代号 2-786  
  
征订热线：010-82341063  
  
  
  
  
  
**漏洞情况**  
  
近日，国家信息安全漏洞库（CNNVD）收到关于OpenSSH安全漏洞(CNNVD-202407-017、CVE-2024-6387)情况的报送。攻击者可以利用该漏洞在无需认证的情况下，通过竞争条件远程执行任意代码并获得系统控制权。OpenSSH多个版本受该漏洞影响。目前，OpenSSH官方已发布新版本修复了该漏洞，建议用户及时确认产品版本，尽快采取修补措施。  
  
## 一漏洞介绍  
  
  
OpenSSH是加拿大OpenBSD计划组的一套用于安全访问远程计算机的连接工具。该工具是SSH协议的开源实现，支持对所有的传输进行加密，可有效阻止窃听、连接劫持以及其他网络级的攻击。该漏洞源于信号处理程序中存在竞争条件，攻击者利用该漏洞可以在无需认证的情况下远程执行任意代码并获得系统控制权。  
  
## 二危害影响  
  
  
OpenSSH 8.5p1版本至9.8p1之前版本均受该漏洞影响。  
  
## 三修复建议  
  
  
目前，OpenSSH官方已发布新版本修复了该漏洞，建议用户及时确认产品版本，尽快采取修补措施。官方更新版本下载链接：  
  
https://www.openssh.com/txt/release-9.8  
  
CNNVD将继续跟踪上述漏洞的相关情况，及时发布相关信息。如有需要，可与CNNVD联系。  
  
联系方式：cnnvdvul@itsec.gov.cn  
  
（来源：CNNVD）  
  
  
  
**分享网络安全知识 强化网络安全意识**  
  
**欢迎关注《中国信息安全》杂志官方抖音号**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1brjUjbpg5wCKFntVibTsmfnGHWYwhZneiclvh29F1PPTmUfne9vmz5XYDfgCGPlA1sBvOSSPSlsTgg3L7Vicicwrw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**《中国信息安全》杂志倾力推荐**  
  
**“企业成长计划”**  
  
  
**点击下图 了解详情**  
  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzA5MzE5MDAzOA==&mid=2664162643&idx=1&sn=fcc4f3a6047a0c2f4e4cc0181243ee18&chksm=8b5ee7aabc296ebc7c8c9b145f16e6a5cf8316143db3edce69f2a312214d50a00f65d775198d&scene=21#wechat_redirect)  
  
  
