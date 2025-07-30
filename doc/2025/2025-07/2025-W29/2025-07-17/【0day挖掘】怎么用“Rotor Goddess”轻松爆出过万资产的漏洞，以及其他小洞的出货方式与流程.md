> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI5NTQ5MTAzMA==&mid=2247484513&idx=1&sn=132993e0a497be205789753df204de55

#  【0day挖掘】怎么用“Rotor Goddess”轻松爆出过万资产的漏洞，以及其他小洞的出货方式与流程  
 天黑说嘿话   2025-07-16 01:04  
  
“这里是雪山盟，感谢各位师傅长期的支持与帮助”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcewKQFGd2JvgS2u18V1ibOVhAzjS04W5sibB8eH3aic5Lhdiapj8Nc1YkFaS8UicBBqWic9lsoqrdCBmAXlg/640?wx_fmt=png&from=appmsg "")  
  
感谢名单：http://zhuanzi.com.cn/thank_you_list.html  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/MwxaTtRUcewKQFGd2JvgS2u18V1ibOVhAAPTzNib8EAhicFKicIekdxfbMrx5SN8GRJ1oOo5Sq5g0zkKiarBlO7otjA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
#------------------------------------------------------------  
  
距离上次发布1.1.0版本的转子女神工具以及过去了一周多，反响还是蛮不错的，用的师傅也不少，BUG也修了特别多，可以说是入不敷出了！  
  
版本也是成功从1.1.0更新到了1.1.6，师傅都称作“转子116”，因为116版本的稳定性比较强，扫描效果距离以前的版本可以说一个天一个地，废话讲完，初衷未变。  
  
“希望这个工具能够名扬四海！”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MwxaTtRUcewKQFGd2JvgS2u18V1ibOVhA6kDX0YtFlDldvVSSaC4wJCaWVN0j5f5P2ibdftqDAOfusgw0vJoPFlA/640?wx_fmt=gif&from=appmsg "")  
  
  
  
#------------------------------------------------------------  
  
  
①首先是0day的出货方式：  
  
说来这个出洞的方式，真是想象不到的简单和顺利  
  
HXW师傅在扫描一个站点的时候，抱着测试工具的心态，却发现了一个可疑的URL  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcewKQFGd2JvgS2u18V1ibOVhA92to96JOCQf5p7m4yFt42FbwXj0gx9I6OSzewlZbmxBDdZb3iblrULw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcewKQFGd2JvgS2u18V1ibOVhAC0k3ovdoaj7GrAYnAh2YayF4nOsmhDo74FAxcBvunnUjvy0VCib12Xw/640?wx_fmt=png&from=appmsg "")  
  
URL比较敏感，并且提示了“可能存在SQL注入”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcewKQFGd2JvgS2u18V1ibOVhACeZMwHicFEAibHVpJhjlsYcBAvDXWeK619klez2sgBaeXaicu1vyyGszA/640?wx_fmt=png&from=appmsg "")  
  
进入后却发现是信息泄露，这里可以水个低危洞，将type的值更改  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcewKQFGd2JvgS2u18V1ibOVhA3XtEmlTvOoiaVrDP3JUB9ZQPDVfZYUiaFPrj1aFm3YcvEu9l0Nkv5TmA/640?wx_fmt=png&from=appmsg "")  
  
意外爆出了XSS漏洞，第二个低危到手，这位师傅又尝试了SQL注入  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcewKQFGd2JvgS2u18V1ibOVhAw9I34t8yx0wKAIf1Z1A4vkBhIKmF8qyonO3kggvbY6q8dqQlofeGzA/640?wx_fmt=png&from=appmsg "")  
  
发现存在SQL延时注入  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcewKQFGd2JvgS2u18V1ibOVhAQzwMs2hm4iatu49aodsVBMC5lPVg3YP0QOdb7fM1jKUGHmk07A6bZdA/640?wx_fmt=png&from=appmsg "")  
  
最终sqlmap一把梭  
  
后面审计框架的时候发现是个0day，意外之喜，一查fofa和quake  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcewKQFGd2JvgS2u18V1ibOVhAKeLibNEETmtnv7eiagFReKaZDPMYpd06I4PfAjOmk7pGib4dyLttP5cGQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcewKQFGd2JvgS2u18V1ibOVhAb3k49C3pGxQNAj22o8CiaAFE5v3QDk1iaqOtxyUtMw4534zfWTNEibaqw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcewKQFGd2JvgS2u18V1ibOVhAdibwdcvuBc4R7RmNaOXfWibEpr7HqD1jjYZYXZyoU6NSeSmdiaHSRVfiaw/640?wx_fmt=png&from=appmsg "")  
  
  
发现影响的资产太多了，师傅正想提交到cnvd但是发现资产不够5000w，就此作罢，当作一次挖洞经验的增加吧！  
  
②第二位师傅的出货方式：  
  
来自。师傅的投稿  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcewKQFGd2JvgS2u18V1ibOVhAz4niaSS5tG6LuTI91TPZfNq51U6JVUWaOnUicS9WemAwjIB440KiaBMwA/640?wx_fmt=png&from=appmsg "")  
  
本来在群里发布工具的相关事宜，聊到其他师傅的出货，这位师傅表示他也同样爆出了个JWT的漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcewKQFGd2JvgS2u18V1ibOVhARgrRG20eHRGIib6u9Cul0RHNDPic07YsrmAXadVBest2HORev2jDhf5Q/640?wx_fmt=png&from=appmsg "")  
  
师傅在进行站点扫描的时候，发现其中一个URL比较可疑，爆出了JWT令牌泄露  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcewKQFGd2JvgS2u18V1ibOVhAhfdIY0wdw2vVKpgHrjyZ4zvOpX2MtxeoYq3qz4eJrTSOmhic2bZHIpQ/640?wx_fmt=png&from=appmsg "")  
  
就立马在威胁匹配里查看参数  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcewKQFGd2JvgS2u18V1ibOVhA04TTZfoOgNtg7fF1wGkOdYD4LPYZxpZibiaVQtofeFU4RTqGVGkdNM9g/640?wx_fmt=png&from=appmsg "")  
  
发现泄露了JWT  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcewKQFGd2JvgS2u18V1ibOVhA3kNvR59lMoAxw19nxp6ph1j5FMm6pqMZ4BDFF5FwSmN3ZCDkNf3wJQ/640?wx_fmt=png&from=appmsg "")  
  
使用该JWT请求页面发现成功返回权限数据  
  
③第三位师傅的出货方式：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUceyG7X0leiaEZO1DX6b0xibar3m3GfCtqjxR6RUXOrQXmD51Xl2B5F5XIG0pjQzXDqiapcN8GvX18Gwkw/640?wx_fmt=png&from=appmsg "")  
  
来自NY师傅的投稿  
  
转子女神扫描站点的时候发现有很多的身份证泄露  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUceyG7X0leiaEZO1DX6b0xibar3sTH8ZGRfHWwLwavg8u2ukfquZajJgsGNXrvSBgHqhPic6TDG142jBlw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcezL4VPU9U05ghXZIM3QRRUiazsUR6kbmmmsXTfxgVp4icmHM3s5LRC5R6W5VHxeKrykmXKN9hFUnLicQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcezL4VPU9U05ghXZIM3QRRUiakz5RAhElvia1ce3eu7Im0wPE8TJBLyiaQDZHaic6zibJ3uibfLBQAAAK2qA/640?wx_fmt=png&from=appmsg "")  
  
无压力的出货信息泄露  
  
-----------------------------------------------------------  
  
以上就到此为止，有需要更详细更多的情报包括转子女神工具的都可以私信我，公众号不方便发太多  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/MwxaTtRUcezL4VPU9U05ghXZIM3QRRUiaicujd9PTVZyricCq8WgI488vBgLnUnKBlcUFekrWRHs1gg8VO54fvEOQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MwxaTtRUcezL4VPU9U05ghXZIM3QRRUiakpspicGxFtIAibU37gz0iaBxhkJDqGwtbJarRNxBbcNRE79JthZLFCpAA/640?wx_fmt=gif&from=appmsg "")  
  
  
   
  
  
  
