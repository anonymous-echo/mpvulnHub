#  如何使用AI进行漏洞挖掘(最终版本)   
_7ingLian  偏远酒馆   2025-02-25 08:42  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/6ibqWGD93gcpYmfRrkHqtZOoLY55mXZWJ16u05arbB1jib4WwY60DN8u3RHWfgYZ3SsSfawBzxkwzjPyb1WibH0og/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
往期文章：  
  
[如何用AI进行漏洞挖掘(一)](https://mp.weixin.qq.com/s?__biz=MzkwMDMwNDgwNQ==&mid=2247485465&idx=1&sn=b348ed780a826686146d0f3c31972d62&scene=21#wechat_redirect)  
  
  
[如何用AI进行漏洞挖掘(二)](https://mp.weixin.qq.com/s?__biz=MzkwMDMwNDgwNQ==&mid=2247485642&idx=1&sn=317337ad87d8d251fcf5450748bf9ba8&scene=21#wechat_redirect)  
  
  
[如何用AI进行漏洞挖掘(三)](https://mp.weixin.qq.com/s?__biz=MzkwMDMwNDgwNQ==&mid=2247485658&idx=1&sn=4cde13c89f470e234da4fb928192b9e2&scene=21#wechat_redirect)  
  
  
  
--->目录<---  
  
0x01——前言  
  
0x02——**最终版本，接入deepseek api实时数据包分析**  
  
  
<table><tbody><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><td data-colwidth="576" width="576" valign="top" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 1px solid rgb(76, 76, 76);max-width: 100%;box-sizing: border-box !important;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(255, 255, 255);font-size: 14px;letter-spacing: 0.544px;text-decoration-style: solid;text-decoration-color: rgb(255, 255, 255);visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><span textstyle="" style="background-color: rgb(255, 255, 255);color: rgb(255, 76, 0);">0x01、</span></span><strong style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;letter-spacing: 0.544px;text-decoration-style: solid;text-decoration-color: rgb(255, 255, 255);visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;letter-spacing: 0.544px;text-decoration-style: solid;text-decoration-color: rgb(255, 255, 255);visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(255, 255, 255);font-size: 14px;letter-spacing: 0.544px;text-decoration: none solid rgb(255, 255, 255);visibility: visible;"><span leaf=""><span textstyle="" style="background-color: rgb(255, 255, 255);color: rgb(255, 76, 0);">前言</span></span></span></span></strong></span></strong></span></td></tr></tbody></table>  
--->  
我在想，AI存在的意义是什么？是打包地球文明？是取代人类干活？还是说？又或许，这一切似乎来得早了些？  
  
  
<table><tbody><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><td data-colwidth="576" width="576" valign="top" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 1px solid rgb(76, 76, 76);max-width: 100%;box-sizing: border-box !important;visibility: visible;"><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><span textstyle="" style="font-size: 14px;background-color: rgb(255, 255, 255);color: rgb(255, 76, 0);">0x02、</span><span textstyle="" style="font-size: 14px;background-color: rgb(255, 255, 255);color: rgb(255, 76, 0);font-weight: bold;">最终版本，接入deepseek api实时数据包分析</span></span></section></td></tr></tbody></table>  
  
--->  
  
在上一版本的基础上新增了deepseek api接入功能。实时访问网站实时分析。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6ibqWGD93gcrcf0rUOJUc1VHdcxbIXddHMzficJhHLF3mqB4nNPTn8iciaBSavTrAQVnmhFE67x8UHJ4dQd2yhtpzw/640?wx_fmt=png&from=appmsg "")  
  
****  
deepseek AI大模型实时分析数据包效果：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6ibqWGD93gcrcf0rUOJUc1VHdcxbIXddHLPHJ7ZNosoBvicSFTWX2E8EV9DbVqDEOU2BrOZIPmGUQiaYh4jlvkIzg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6ibqWGD93gcrcf0rUOJUc1VHdcxbIXddH2GSfFVI4bCQGB4qcsxEQEv0XC6GgicstcegVYfO09LBMWZjZE8Xeepg/640?wx_fmt=png&from=appmsg "")  
  
****  
****  
**已完结，该主题不再更新**  
  
  
