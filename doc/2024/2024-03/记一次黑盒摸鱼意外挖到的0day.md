#  记一次黑盒摸鱼意外挖到的0day   
长相安  白帽子左一   2024-03-24 12:00  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFbaUgVwdsriauB77CgQS8lyBNAxtx9IMqJQdhuuoITunu8A5Gp7kFjF7BvEXSaLMuDTYhnu7Nicghg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
## ## 一、前言 本文所涉及的漏洞已提交至CNVD并归档，涉及站点的漏洞已经修复，敏感信息已全部打码。## 二、漏洞挖掘过程 随手摸鱼，开局fofa搜一波系统管理然后海选，相中了这个xx系统管理中...  
```
文章来源: https://forum.butian.net/share/202
文章作者：长相安
如有侵权请联系我们，我们会进行删除并致歉
```  
## 一、前言  
  
本文所涉及的漏洞已提交至CNVD并归档，涉及站点的漏洞已经修复，敏感信息已全部打码。  
## 二、漏洞挖掘过程  
  
随手摸鱼，开局fofa海选，相中了这个xx中心。![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHlKT16icufYiaYw7zMwyY09ppqM7eM9MHcj2zkbIFbAPUcNuBateiajeBhr8um3KgRXknFRib38qy8jA/640?wx_fmt=png&from=appmsg "")  
登录框嘛，老规矩，掏出大字典跑一波弱口令![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHlKT16icufYiaYw7zMwyY09pyKo9ibZboWYFmSt7QMXsOMCRE1icPG1qSDAuZpZC1ZDr1BicMxY224szg/640?wx_fmt=png&from=appmsg "")  
emmm，发现密码是加密的，并且加密脚本也没有写在前端，但是没关系，用户名还没加密，本来就是随手摸鱼，输一个最常见的弱口令123456，然后掏出我的用户名大字典（其实众所周知很多时候密码跑不出来改为跑用户名会有大惊喜）。![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CBJYPapLzSHlKT16icufYiaYw7zMwyY09pI4ZxEdiccIJWqc81DNBibkFH8LywDa4zznYIIickXib4yXCPiaiaPVbT00UA/640?wx_fmt=jpeg&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHlKT16icufYiaYw7zMwyY09puPqvhZquaqLmaUBw8TKeePLA1Mhiaf6oTBibk1nMgY50icCyibCEia0JBpQ/640?wx_fmt=png&from=appmsg "")  
好家伙，经典test用户，开门红，摸进去看一下，界面长这样![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHlKT16icufYiaYw7zMwyY09peITqdibLemicibItJwbW3ZlbuXTXdqz8FX5lw5jFPZDQ7r0a8cK58InMA/640?wx_fmt=png&from=appmsg "")  
看了一圈没什么太值得注意的地方，于是点了一下信息保存![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHlKT16icufYiaYw7zMwyY09pibpIuyMRdO8jq00Cw3oMN0ajic59Een17g3Gn8U921UzrziaTSIfMia88Q/640?wx_fmt=png&from=appmsg "")  
这里挨着测了下sql和xss，嗯，都没有![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CBJYPapLzSHlKT16icufYiaYw7zMwyY09pFQHWB4Xc4TXNQJf731bia7heyk3Va6Q4Cr4poZwfK4Eic0FWvYiaqRGYA/640?wx_fmt=jpeg&from=appmsg "")  
回过头来看着这个userId参数，直觉告诉我这里得出一个经典的越权漏洞。先放着，修改了一下loginName和userName两个参数为admin，发现页面没有任何变化，然后修改了一下userId，随手打了个002110，还是没啥变化emmm，反手把这个参数丢进Intruder从 001980遍历到002100，最终发现当userId为002000时，用户可成功越权至admin用户![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHlKT16icufYiaYw7zMwyY09pC2cXzqrU17XDlVHq4o86rI8gNvCvcEhJiauP9cEfK7tSnOFmdZD7icgA/640?wx_fmt=png&from=appmsg "")  
测到这里本来准备交洞下播了，又突然想到这个系统怕不是目标单位自己开发的，于是到首页找了下特征fofa一波![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHlKT16icufYiaYw7zMwyY09pY46Sl9Vn2VV4ygTnGKMIyibKibgmQMlqmngy18zxnJfBsrRRIR9V8bmQ/640?wx_fmt=png&from=appmsg "")  
好家伙，281个站点，顺着网去找了下公司，发现这个洞各项要求都符合颁发证书的条件，于是反手提交CNVD并嫖了个证书。![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CBJYPapLzSHlKT16icufYiaYw7zMwyY09poKMrciby0hNMYbmXbumewKteibYibCeY1eXXhicqa2IsXDk7z5dxibugxFw/640?wx_fmt=jpeg&from=appmsg "")  
  
## 三、结语  
  
黑盒摸鱼，纯属运气。日常挖洞中遇到什么xx系统、xx管理中心出洞的时候都可以找特征fofa一波试试，涉及大量站点那就赚翻了~  
  
  
声明：⽂中所涉及的技术、思路和⼯具仅供以安全为⽬的的学习交流使⽤，任何⼈不得将其⽤于⾮法⽤途以及盈利等⽬的，否则后果⾃⾏承担。**所有渗透都需获取授权**  
！  
  
**如果你是一个网络安全爱好者，欢迎加入我的知识星球：zk安全知识星球,我们一起进步一起学习。星球不定期会分享一些前言漏洞，每周安全面试经验、SRC实战纪实等文章分享，微信识别二维码，只需25，即可加入，如不满意，72 小时内可在 App 内无条件自助退款。**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGpTtick8dYImTUOcmaQWHRzkPIp7SwgncysYUIo0cKZAcHvXcMEBL5ZZEJCIpUP08SGOR8bnejDxQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSE3xxjQrLXjiaAWoqibdM1AFZ0uePzzUOG049bSjeEkbft1NfIm833fQ0ibIbW5IoE2ftnWoS3YxRPLg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
