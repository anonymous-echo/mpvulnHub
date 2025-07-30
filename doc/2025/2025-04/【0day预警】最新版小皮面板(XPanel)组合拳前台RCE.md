#  【0day预警】最新版小皮面板(XPanel)组合拳前台RCE   
 sec0nd安全   2025-04-26 02:26  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPlzg5sZKIlTPHGFlkF53seUMNUsR3TKcn9VGDeJTwzichS2dI31pVDLibP6XhejxiakNbBahbqtchM5A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/QtaE6uFmibPlzg5sZKIlTPHGFlkF53seUgwlRhqQibojuE58lklgLm1hpT7yT88speo9QwTL6dlaFNdP9TvsdL9Q/640?wx_fmt=gif&from=appmsg "")  
  
点击上方蓝字·关注我们  
  
  
免责声明  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/QtaE6uFmibPlzg5sZKIlTPHGFlkF53seUZHdTe6rSPrTwIbY4nGDic3ick7JK8o2LnQqAYibZia3uZmzNvdMZiciaZMPw/640?wx_fmt=gif&from=appmsg "")  
  
  
由于传播、利用本公众号  
菜狗安全  
所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号  
菜狗安全  
及作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，会立即删除并致歉。  
  
前言  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/QtaE6uFmibPlzg5sZKIlTPHGFlkF53seUZHdTe6rSPrTwIbY4nGDic3ick7JK8o2LnQqAYibZia3uZmzNvdMZiciaZMPw/640?wx_fmt=gif&from=appmsg "")  
  
  
**文章由交流群匿名大手子投稿**  
  
**漏洞详情作者已复现确认存在**  
  
文章目录  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/QtaE6uFmibPlzg5sZKIlTPHGFlkF53seUZHdTe6rSPrTwIbY4nGDic3ick7JK8o2LnQqAYibZia3uZmzNvdMZiciaZMPw/640?wx_fmt=gif&from=appmsg "")  
  
  
```
项目介绍
漏洞详情
    漏洞概述
    漏洞细节
    漏洞影响
漏洞复现 
最后        
```  
  
# 项目介绍  
  
小皮面板（XPanel）、phpStudy为河南小皮安全技术有限公司旗下产品，小皮面板（XPanel）面向Linux服务器运维领域，于2024年基于全新技术架构升级重构，产品定位是提供稳定、安全、简单易用的Linux服务器运维体验，phpStudy诞生于2007年，是一款老牌知名的PHP开发集成环境工具，产品历经多次迭代升级，目前有phpStudy经典版、phpStudy V8（2019版）小皮项目成立至今，始终坚持以公益为主导，秉持永久免费的产品理念。靠着一点点口碑的积累，小皮产品成了众多站长和开发者们的首选工具。  
  
fofa  
：  
icon_hash="-1458616391"  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPlfsSibH2ia8ibAmG1CYSOvJmhhj0uycQIBkInI38XLkjR8U9DEMVsdVoHiblmk936a3ft9M4Ogf66iaqw/640?wx_fmt=png&from=appmsg "")  
  
由于小皮面板搭建后端口是随机开放的，fofa探测不全，实际资产远不止这些  
# 漏洞详情  
#### 漏洞概述  
  
小皮面板（XPanel）最新版存在**鉴权绕过漏洞**  
，攻击者可构造恶意请求直接访问后台管理接口，结合**任意文件下载漏洞**  
获取数据库文件，并从中提取SSH私钥，最终实现**远程服务器接管（RCE）**  
，造成严重安全风险。  
#### 漏洞细节  
1. **鉴权绕过**  
  
1. 攻击者可通过构造特殊HTTP请求，绕过身份验证，直接访问后台敏感路由。  
  
1. 影响范围：未授权用户可执行管理员操作，如系统配置修改、服务启停等。  
  
1. **利用后台功能获取敏感数据**  
1. 由于权限被绕过，攻击者可访问**文件下载功能**  
（系统正常功能，但本应仅限管理员使用  
）  
1. 通过下载数据库配置文件（如：  
/xp/db/app.db  
）  
获取存储的SSH密钥或数据库凭据。  
  
1. **SSH密钥泄露与服务器接管**  
  
1. 数据库存储SSH密钥（如authorized_keys  
或私钥文件路径），攻击者可利用泄露的密钥直接通过SSH登录服务器，获取**root权限**  
，进而植入后门、窃取数据或横向渗透内网。  
  
#### 漏洞影响  
- 影响版本  
：XPanel 最新版  
  
- 攻击复杂度  
：低（无需交互，可自动化利用）  
  
# 漏洞复现  
# 权限校验绕过：通过修改登入返回包信息绕过权限校验直接登入后台  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPlfsSibH2ia8ibAmG1CYSOvJmhQhnX6muSibVUPDaMiaGicric63v6To7W39w0nZotLu5uf2Rr8E88Zt7iaaQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPlfsSibH2ia8ibAmG1CYSOvJmh903yZMXMHHXcrINyDEDbsPCicTpZDkyPUQcveMp6iad4s8FOcKuQsCtw/640?wx_fmt=png&from=appmsg "")  
  
成功登入，并且不会由写入登入日志中  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPlfsSibH2ia8ibAmG1CYSOvJmhiahks30ibhcfRT6HTvXyAQUHAOuyuTTjAGqH2KkPcf4dduS91JoJCcNw/640?wx_fmt=png&from=appmsg "")  
  
登入成功后下载数据库文件：xp/db/app.db  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPlfsSibH2ia8ibAmG1CYSOvJmhJdxhT1CFFFBHkHbq78aXeLBs1RJJU4kWibDmWw1EONkFPXEhoNLGRwQ/640?wx_fmt=png&from=appmsg "")  
  
下载到本地打开，terminals表中存放有SSH远程连接的KEY，可以用于远程连接  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPlfsSibH2ia8ibAmG1CYSOvJmhZPZxdXJ3pkeTCJMsmV7iaRiaVKkuOic6Ssicx1wU0mxChCFvgKWvMstUVA/640?wx_fmt=png&from=appmsg "")  
  
这里权限绕过进后台后，小皮面板后台自带命令终端，直接就可以执行命令了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPlfsSibH2ia8ibAmG1CYSOvJmhUCXZljMyPEjLqP2UQSKekL80SjBzvTxvsbjK8SER2s3qrB9MjEkaNg/640?wx_fmt=png&from=appmsg "")  
  
也可以采用远程私钥连接  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPlfsSibH2ia8ibAmG1CYSOvJmhuKwopxyOhr4RXnwDVQFqWGmNuoYC4J5mY8OXdQ3ibks20wPP0GVImRA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPlfsSibH2ia8ibAmG1CYSOvJmhAYBlmxzv9YBqpXOZSjmxBUwnXRg52zYnNNAVu0ZfpFZZhuVicibLfNjg/640?wx_fmt=png&from=appmsg "")  
# 最后  
  
二期公开课  
《PHP代码审计速成》持续更新中...  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPkp2zicq3IJiajmo3kicxXOWwdFP3GjBSVIg2gNk5ONfHTNn4JHXribia3rhzrbRccXcMegoviaYBtZYIibA/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
# 直播通知和课件都会在交流群中发布，有需要的师傅可以加我VX，备注：交流群，我拉你进群  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/QtaE6uFmibPmic8RYXMickJZbXfFDicmYbdzTb4XdVfibZH9IicN9uAezcmaqbHLP929dS7AfmybpqpczicmicZzNM42AQ/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
性感群主不定期在线水群解答问题  
  
  
