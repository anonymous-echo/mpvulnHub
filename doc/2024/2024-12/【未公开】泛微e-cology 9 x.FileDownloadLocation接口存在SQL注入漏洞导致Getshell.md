#  【未公开】泛微e-cology 9 x.FileDownloadLocation接口存在SQL注入漏洞导致Getshell   
原创 xiachuchunmo  银遁安全团队   2024-12-16 18:34  
  
**需要EDU SRC邀请码的师傅可以私聊后台，免费赠送EDU SRC邀请码（邀请码管够）**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
**漏洞简介**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
******泛微E-COLOGY是一款由中国泛微软件系统股份有限公司开发的企业协同管理软件，为中大型组织创建全新的高效协同办公环境，智能语音办公，简化软件操作界面、身份认证、电子签名、电子签章、数据存证让合同全程数字化。泛微e-cology 9 x.FileDownloadLocation接口存在SQL注入漏洞**  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
**资产测绘**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
```
body="/sys/common/pdf/pdfPreviewIframe"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yeJvia5dNx5ibzXpdiaWQ4jzn0ovSGTAxrvnFjicl8DFTZnaiaR4aGLwXRH2QGUCqlMWRNkW4HcDIgyvOZ5DCU1BPDQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yeJvia5dNx5ibzXpdiaWQ4jzn0ovSGTAxrviaZIU6qZGjCDkG9CZNSAqROrOgNgmm0c3Eq3IpqLVc4dMId4icnMHLhA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
**漏洞复现**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
**通过注入获取corpid、corpsecret测试**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yeJvia5dNx5ibzXpdiaWQ4jzn0ovSGTAxrvT6SUVNuHhUWgVwEE88HB1Xmuqib1Qn933Yl1DwWrgmbBtuLIK3PBD6w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
**SQLMap测试**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yeJvia5dNx5ibzXpdiaWQ4jzn0ovSGTAxrvAyiciaXiczAZ6Jc7XaDuDFDHY9t5lDQrBc0Lfvv9D3iaat17owjXArOkKQ/640?wx_fmt=png&from=appmsg "")  
  
**获取当前数据库名测试**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yeJvia5dNx5ibzXpdiaWQ4jzn0ovSGTAxrvJIIpSkpJMkL3b47iaM1VJxYiaGqFlvKe96ycLzq5PIS2USicprAHyq7BA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
**Getshell测试**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yeJvia5dNx5ibzXpdiaWQ4jzn0ovSGTAxrv2avuYBcJuEoosHOSf3BKSlx7c2gSm4tEtdGFnQPAAqnxJkMLWdksqw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
**Nuclei测试**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yeJvia5dNx5ibzXpdiaWQ4jzn0ovSGTAxrv61Cld0OLDK3DiaK0AqPCTZibKnACIQaQOUJg3ic3lhxUZ7VZUvnOvlsTw/640?wx_fmt=png&from=appmsg "")  
  
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
**CNVD通用证书**![](https://mmbiz.qpic.cn/sz_mmbiz_png/yeJvia5dNx5ibLtno2E9f9Hrfy3OTwkibdYL67H7TpeCUn2vcrksmcLiaTic0aJYhTLmTrIa5iazMGRLDvf9nNibdsPxA/640?wx_fmt=png&from=appmsg "")  
**一起愉快的刷分**![](https://mmbiz.qpic.cn/sz_mmbiz_png/yeJvia5dNx5ibLtno2E9f9Hrfy3OTwkibdYhIQWPUxibC3y9ib8BqibgCicNM6KFuG095GB0yFj3ASZ6qXvp84IZAMSdw/640?wx_fmt=png&from=appmsg "")  
**欢迎加入“安全安全”EDU团队**![](https://mmbiz.qpic.cn/sz_mmbiz_png/yeJvia5dNx5ibLtno2E9f9Hrfy3OTwkibdYpQpW4JVxVHoJej6E06ODldaeYjRv0crOWzBlLYcgy9cElwwSk3Dl1A/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
**免责声明**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/HVNK6rZ71oofHnCicjcYq2y5pSeBUgibJg8K4djZgn6iaWb6NGmqxIhX2oPlRmGe6Yk0xBODwnibFF8XCjxhEV3K7w/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
文章所涉及内容，仅供安全研究与教学之用，由于传播、利用本文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。  
  
