#  【技术分享】关于C-Lodop打印服务文件读取漏洞修复方式   
原创 剁椒Muyou鱼头  剁椒Muyou鱼头   2024-11-29 01:17  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/92Yia6FpSFA2QiaAzq0Dumm39PGIsC7mk4lX6c4yYnERUGvnHo7SQreGiboYBj0ib7TlaUx1DKtEGlU8mqS9ZtLZRw/640?wx_fmt=gif "")  
  
**阅读须知**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/92Yia6FpSFA2QiaAzq0Dumm39PGIsC7mk4lX6c4yYnERUGvnHo7SQreGiboYBj0ib7TlaUx1DKtEGlU8mqS9ZtLZRw/640?wx_fmt=gif "")  
  
  
****  
**本公众号文章皆为网上公开的漏洞，仅供日常学习使用，未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作。利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责。**  
  
朋友们现在只对常读和星标的公众号才展示大图推送，建议大家把**剁椒Muyou鱼头**“设为星标”，否则可能就看不到了啦！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA2hvEA8gEIeGOEiba9uWicXD01hM2Bw8oTpcNCZl68Bj8T0aLpOHAMFCv9Qd6KeeQgTscOURdQUDbLw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/92Yia6FpSFA2QiaAzq0Dumm39PGIsC7mk4Z7hc6oGV6C6IwibzfQUM1oq1yUciadAKQ3Ap29o8GGnBU52wXgSSicBxQ/640?wx_fmt=gif "")  
  
  
****  
**2024/11/29 星期五**  
  
**晴·****西北风4级**  
  
  
//01 C-Lodop打印服务工具  
  
  
      
C-Lodop云打印服务器是一款云打印工具，该软件功能强大，支持Lodop的全部语法，且C-Lodop云打印服务器兼顾各种普通打印机、本地串口的、并口的、网络共享的。服务运行稳定，可超级巨量连续打印，承载高端业务。安装文件仅2M多，体积小，服务安装部署简单，几乎一键完成，零配置，这一特点为本地安装替代控件功能奠定了基础，几乎和控件安装类似。安装之后可以接收本地或者其他客户端浏览器的远程打印任务了，而且它可以免登陆使用，在使用过程中可以调试窗口，体验AO打印机在内的扩展服务。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA2hvEA8gEIeGOEiba9uWicXD0dDIArQBjiaeDUF2V1xSaeOPTXOuVDt3ia6ZYGXx4AlvYgKpPf9HejeTw/640?wx_fmt=png&from=appmsg "")  
  
  
//02 C-Lodop打印服务文件读取漏洞  
  
  
    泰安梦泰尔软件有限公司C-Lodop打印服务系统存在文件读取漏洞,攻击者可利用该漏洞获取敏感信息。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA2hvEA8gEIeGOEiba9uWicXD0FwFxeWeyu4DoOc2KyLbFqIsW7D02baF2N6ibdtHWoQfFP5tdgYSXiapw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA2hvEA8gEIeGOEiba9uWicXD0ric15mxeT35RzR0gwhpL0Sq2GQ67DaSSBqFaicwwdAWnG0YcP833s5Dw/640?wx_fmt=png&from=appmsg "")  
  
  
//03 C-Lodop打印服务默认开启端口  
  
  
    C-Lodop打印服务默认开启8000，18000，8443三个端口，所以可能会出现漏洞扫描时同一IP不同端口爆出多个相同漏洞，可以针对三个端口扫描处理网内相关漏洞。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA2hvEA8gEIeGOEiba9uWicXD0yuFKD71JJZ8aZW1BXztUkrVdWSV1iaiat7aow9D952u9l6fTkqkZOYzA/640?wx_fmt=png&from=appmsg "")  
  
  
//04 C-Lodop打印服务漏洞修复方式  
  
  
    1.如果无需使用此工具服务，控制面板卸载该安装程序即可，卸载不影响正常打印使用。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA2hvEA8gEIeGOEiba9uWicXD0OIczxQxRdaicPHULjMmuKAic9QE8kVDTdstPgyktqzT4BXpLvJJTBsQg/640?wx_fmt=png&from=appmsg "")  
  
  
    2.  
如果需要此扩展程序额外功能，可前往官网下载6.0版本进行覆盖安装，最新版本已修复此漏洞。官网下载地址：http://www.c-lodop.com/download.html  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA2hvEA8gEIeGOEiba9uWicXD03sn9qjOUlrdYpAIOmukdhbGF46UK8eLAMedwWlkmib4ZHlwjN4vw0fg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA2hvEA8gEIeGOEiba9uWicXD0b8ciaS1cFiaI9mZ3Al56aDiaibiaDS6EibzkTubkiaE9EBy61F0xI7sxXviayQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
    
END   
  
  
   
作者 | 剁椒Muyou鱼头   
  
I like you,but just like you.  
  
我喜欢你，仅仅如此，喜欢而已~  
  
  
  
  
**********点赞在看不迷路哦！**  
  
  
