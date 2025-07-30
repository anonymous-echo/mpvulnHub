#  【0day】电子图书阅读平台downFile存在SQL注入漏洞   
xiachuchunmo  银遁安全团队   2024-12-01 22:00  
  
**需要EDU SRC邀请码的师傅可以私聊后台，免费赠送EDU SRC邀请码（邀请码管够）**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
**漏洞简介**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
**电子图书阅读平台****提供了超过千万册图书的在线阅读服务。其界面简洁，搜索功能强大，用户只需输入书名即可快速找到对应的电子书资源，并可选择多种格式进行下载阅读。它支持中文搜索，资源极其丰富，几乎涵盖了所有领域的书籍。用户可以在这里轻松找到并阅读自己需要的电子书。电子图书阅读平台存在SQL注入漏洞.**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
**资产测绘**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
```
body="/Index.aspx/SearchBy"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yeJvia5dNx5iccAtic0Qdu6IzaUL5lwC3iaOKick9hbxCfWcDdakw2RZFrF0efZMtx03ycRWWquY5wZ8VMSibpGxO1LQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
**漏洞复现**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
**注入测试**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yeJvia5dNx5iccAtic0Qdu6IzaUL5lwC3iaO4AjGFVqsf96LicartnHia6Libdtp6lCUWzV5yBrJD9UvYSob2bbW8T5sA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
**SQLMap测试**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yeJvia5dNx5iccAtic0Qdu6IzaUL5lwC3iaOO27lmkOibFKYrlNmlFsW53o8AzH9INxhGB3z6LljibjcFAxhMiagzz9sA/640?wx_fmt=png&from=appmsg "")  
  
**获取当前数据库名测试**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yeJvia5dNx5iccAtic0Qdu6IzaUL5lwC3iaO8zIa36Tn1hVl1uPibQP8Kt5icALgSXNFZa5Dd70Vkibdvl08kFVSvvSuw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
**Nuclei测试**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yeJvia5dNx5ibtLsZ2Mo1PKdl6BFJOkS64LohibXdQA2VC9JxvNXToPy8uA2cGJty3VUS7qU7JLicpnUicS0Kn4LviaQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
**圈子介绍**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
高  
质量漏洞利用工具分享社区，每天至少更新一个0Day/Nday/1day及对应漏洞的批量利用工具，团队内部POC分享，星球不定时更新内外网攻防渗透技巧以及最新学习研究成果等。  
如果师傅还是新手，内部的交流群有很多行业老师傅可以为你解答学习上的疑惑，内部分享的POC可以助你在Edu和补天等平台获得一定的排名。  
如果师傅已经  
是老手了，有一个高质量的LD库也能为你的工作提高极大的效率，实战或者攻防中有需要的Day我们也可以通过自己的途径帮你去寻找。  
  
**【圈子服务】**  
  
1，一年至少365+漏洞Poc及对应漏洞批量利用工具  
  
2，Fofa永久高级会员  
  
3，24HVV内推途径  
  
4，Cmd5解密，各种漏洞利用工具及后续更新，渗透工具、文档资源分享  
  
5，内部漏洞  
库情报分享  
（目前已有2000+  
poc，会定期更新，包括部分未公开0/1day）  
  
6，加入内部微信群，认识更多的行业朋友（群里有100+C**D通用证书师傅），遇到任何技术问题都可以进行快速提问、讨论交流；  
  
  
圈子目前价格为**129元**  
**(交个朋友啦！)**  
，现在星球有近900+位师傅相信并选择加入我们，人数满1000  
**涨价至149**，圈子每天都会更新内容。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/yeJvia5dNx5ibmJXuUnaww610JyW2aMD7XyghxoOEL12QTuKPMtygJ7abCibjickyRUpBPDf52hoXPRu3nWEmjzt5A/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
**圈子近期更新LD库**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yeJvia5dNx5ibvkW4kOOKEsgsWAVmfnvfMe3v0zbgAeT2YIhMjC9bNibjDfM2iaX1KBIPj20hjxAgv5zSN70prQbnw/640?wx_fmt=png&from=appmsg "")  
  
**每篇文章均有详细且完整的手工WriteUp****（跟其他只有POC，没有验证截图的不一样）**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/yeJvia5dNx5ibK7Dv4GdXpIuKGmLtjmiaeQuz0vbaPubOpv3oWAehI3Pr5flA7KQSUWtKIyycZezdAxmic5rpy2tHw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**星球提供免费F**a**![](https://mmbiz.qpic.cn/sz_mmbiz_png/yeJvia5dNx5ic3icibHW6nDoAAoX9Spv9mREyEWTD0kRZWwApI2LKZDlqDfFj0Hnbja85ppeKPty1oOKFD80G5iadWQ/640?wx_fmt=png&from=appmsg "")  
**C**D通用证书********一起愉快的刷分**![](https://mmbiz.qpic.cn/sz_mmbiz_png/yeJvia5dNx5ibz6ibFL4b8QBThc3t0ok0Gb7jsseWcrYsxNbv9qyQ0uhDib7TkUcLIIos2iaYlzL6TcF3ia2Rric1EH1g/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yeJvia5dNx5ickvP43lKosLxs8SB5kCSQQEP05NRM08qqN1YIrU1QF8ILRniaF4Vu2jbHhTypliczTnEuK5TXobk9A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
**免责声明**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
  
  
