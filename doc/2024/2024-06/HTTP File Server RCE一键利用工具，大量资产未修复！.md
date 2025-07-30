#  HTTP File Server RCE一键利用工具，大量资产未修复！   
原创 深潜sec安全团队  深潜sec安全团队   2024-06-13 18:30  
  
## 前言  
  
HFS
 是一款有着 20 年历史的老牌文件分享工具，全称 Http File 
Server，它会在你的电脑上启动一个文件服务器，通过浏览器就能方便的下载文件，非常简单易用。开发者近半年以来完全重建了代码，并启用了 HFS 3
 这个新名字，带来了更多新特性，包括 https、权限系统、插件系统等功能。  
## 漏洞描述  
  
HTTP File Server RCE存在未授权接口，利用未授权接口可以执行系统命令，最终获取服务器权限。造成权限丢失和数据泄露等危害。  
## 影响范围  
  
这个漏洞理论上影响的所有版本：HFS 2.3 betaHFS 2.3dHFS 2.3mHFS 2.3kHFS 2.4.0 RC6HFS 2.4.0 RC7除此之外其他的HFS2版本官方已经不再维护了，但是理论上来说他们都受到这个影响  
## 漏洞复现  
  
1.信息收集  
  
通过fofa搜索对应的资产，可以看到资产列表>14w，漏洞利用范围比较广泛  
> fofa：app="HFS"  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bfMXBp6QpdxKAcjDhcv4fo2M2n4kjHCfysWuhLQbdTOQhbUUsh5II5iaSepeWiaxLIuN3wI4AXXfad7Z3DBpPq3g/640?wx_fmt=png&from=appmsg "null")  
  
1.访问网站的主页信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bfMXBp6QpdxKAcjDhcv4fo2M2n4kjHCfJn5coWbLMBjLrZkMUz8Kzbf3HfKlT751bfuf0xGa58KR5IKZhz9cOQ/640?wx_fmt=png&from=appmsg "null")  
  
1.利用HFS-tool工具实现漏洞利用，成功执行系统命令  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bfMXBp6QpdxKAcjDhcv4fo2M2n4kjHCfB5KWEZ4Loicxa46YU6LgqAy1eGqH24lMqpTAVqRbraqfDriaqCYwick2g/640?wx_fmt=png&from=appmsg "null")  
  
**关注微信公众号回复HFS获取POC**  
  
**原工具地址：**  
  
**https://github.com/10cks/hfs-exp-tool**  
  
****  
****  
