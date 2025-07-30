#  单兵漏洞测试工具 -- Yakit   
W4nk3r  Web安全工具库   2024-12-03 16:01  
  
Yakit，一个集成化的单兵漏洞测试工具，也是我用起来较为顺手的一个测试工具，  
  
今天想从最基本的环境配置到漏洞挖掘中的实战一步步进行讲解  
  
环境配置:yakit提供两种mitm中间人攻击环境配置  
  
一种是无环境配置，另一种是有环境配置  
  
无环境配置:电脑上下载谷歌浏览器，然后点击免配置启动，直接可以抓取数据包，可谓很方便了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3Uibs7E9m0VQibAhSMt4qIMCQ5nbRgwZkibr1O9kMRdLbRiaTQT82XY80KkUeYNBnRVHzuP5ibQf0aNj1NLQ/640?wx_fmt=png&from=appmsg "")  
  
有环境配置:这一步和burp操作一模一样  
  
首先，下载证书  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3Uibs7E9m0VQibAhSMt4qIMCQ5nV548WsRJTaia8y3ziaB9oz7kaiacGInbaGasXglM0rrddpaEKMOmo3h1A/640?wx_fmt=png&from=appmsg "")  
  
然后，打开火狐浏览器的设置，输入net，这一步设置我们的代理  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3Uibs7E9m0VQibAhSMt4qIMCQ5nEJwtfcpJibKWFaTILlIXAY5kTVj9SmV4JJ6ylZUYjxmkKCGMdObO5lg/640?wx_fmt=png&from=appmsg "")  
  
设置如下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3Uibs7E9m0VQibAhSMt4qIMCQ5nQWuLhAPhlTU0wGfL2n8TbQmH0Ihv4q9otMn9DRKf0jmN2EQsg9Da8Q/640?wx_fmt=png&from=appmsg "")  
  
下载插件，找到这个变蓝的代理插件，第一个推荐的代理插件也可以使用，看个人喜好  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3Uibs7E9m0VQibAhSMt4qIMCQ5nj3Bjt2d3iciaibtSjuicyN19ibmicX9bNNFSQQKvQ76DGmqOkF0vFaib8VlaQ/640?wx_fmt=png&from=appmsg "")  
  
进行如下设置，名字可以随便起一个很好辨认的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3Uibs7E9m0VQibAhSMt4qIMCQ5njHgkXibXgt85YQoibVGQvichGhQlh8oqm9ibaWibYOHSQgNO0PHYjSdPyOg/640?wx_fmt=png&from=appmsg "")  
  
最后一步，导入证书，设置->隐私与安全->查看证书  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3Uibs7E9m0VQibAhSMt4qIMCQ5nxNdtskPtVkKMdfA11VsnyeHIqVL5KIOIlnRl5H1pEvf9VTAng85ib9A/640?wx_fmt=png&from=appmsg "")  
  
这一步点击导入，找到你下载证书的文件，点击导入后然后会出现两个选项，都选，不然有概率出现抓不到包的情况  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3Uibs7E9m0VQibAhSMt4qIMCQ5nNPEENoiaapeOicv1KhvvYCgIGYqtnNteibvRm55RenSAWorWjhXyakSJw/640?wx_fmt=png&from=appmsg "")  
  
OK，大功告成，这里可以看到我们抓取的流量  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3Uibs7E9m0VQibAhSMt4qIMCQ5n4ia5v6EicDficXYxSQtR4p3otgQhTbJO1C4gF2JOIF9ELnAgQza8LbE6g/640?wx_fmt=png&from=appmsg "")  
  
tips:有师傅可能会出现白茫茫(打开页面一片白),但是能抓取流量,这里可以看一下插件的配置是不是将http设置为https了  
  
  
实战  
  
FUZZ(模糊测试),点击这个按钮，可进行数据包重放，查看回显，通过向目标网站发送可导致漏洞的数据并监视异常结果来发现网站的漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3Uibs7E9m0VQibAhSMt4qIMCQ5nGC3ZbRUobsCDiaEzrnDqIRA2r3apEnXyF7QJjyJ24P4E90pIYBZ1IQA/640?wx_fmt=png&from=appmsg "")  
  
Codec  
  
这里可以将代码进行加密，一般在设有waf的网站进行绕过操作的时候将代码进行加密处理，同时也可以将获取的token值或者疑似身份认证的值尝试解密  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3Uibs7E9m0VQibAhSMt4qIMCQ5n1ic9Gg1AXUOBJLnxPKLAhbzLkJTPFx0ibJD4dsgICOxeXGiawApu2Eumw/640?wx_fmt=png&from=appmsg "")  
  
编码与解码，快速加解密的工具，跟Codec作用差不多，不过可以直接复制粘贴  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3Uibs7E9m0VQibAhSMt4qIMCQ5nbRgwZkibr1O9kMRdLbRiaTQT82XY80KkUeYNBnRVHzuP5ibQf0aNj1NLQ/640?wx_fmt=png&from=appmsg "")  
  
  
该内容转载自网络，仅供学习交流，勿作他用，如有侵权请联系删除。  
  
转载地址：https://www.anquanke.com/post/id/300674  
  
  
**各 类 学 习 教 程 下 载 合 集**  
  
  
  
  
  
  
  
  
  
https://pan.quark.cn/s/8c91ccb5a474  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibuuhdO7GMx4wqK5PQMWgr8pNaudBlYJUYXP6R6LcL0d3UYmPLoiajIXwaibhvlchGibgiaBGwMSwuq58g/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
  
