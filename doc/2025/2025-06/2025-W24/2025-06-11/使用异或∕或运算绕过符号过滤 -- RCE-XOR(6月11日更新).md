#  使用异或/或运算绕过符号过滤 -- RCE-XOR(6月11日更新)  
pluvo070  Web安全工具库   2025-06-11 16:02  
  
暗月渗透测试33 项目实战渗透合集实战项目四 完整的渗透测试实例  
  
链接：https://pan.quark.cn/s/cff5e3567c0a  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibtgSYh1zRPDdoGhKc8dQQDZnXVhywNtNzGb5yfREYFXvfsicjpyuwWHRtn3a9DRJNewA5werDiasUng/640?wx_fmt=png&from=appmsg "")  
  
===================================  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，  
安全性自测  
，  
大家都要把工具当做病毒对待，在虚拟机运行。  
如有侵权请联系删除。个人微信：  
ivu123ivu  
  
  
**0x01 工具介绍**  
  
使用异或/或运算绕过符号过滤。  
  
**0x02 安装与使用**  
1. test-xor.php 模拟靶场，URL 传参并过滤所有数字和大小写字母，后续使用代码执行函数执行该参数（而非命令执行函数，因此后续需要嵌套命令执行函数）  
  
1. 用符号异或并 URL 编码绕过：运行 rce-xor.php，获得列表 rce-xor.txt  
  
1. 运行脚本 rce-xor.py，输入函数：system  
，输入命令：ipconfig  
，获得 Payload  
  
1. 通过查询参数传递：test-xor.php?cmd=Payload;  
  
1. 成功 RCE ![图片不见了](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibtgSYh1zRPDdoGhKc8dQQDZffeh0tOlhEofqUXADgicgemWJsZlicCJw4QichZ2icAM4GicR0E1AZ9oBzw/640?wx_fmt=png&from=appmsg "")  
 对于或运算版本，使用 rce-or.php 和 rce-or.py 脚本即可  
  
不仅仅是工具库  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/8H1dCzib3Uibu7uX2oYjbbibndft14nzUMIoRia7UqCAgMXSZAu1iaBDWSWLLuFnyibwfOiaCLO7YXaC6qib8icgHXwoe3Q/640?wx_fmt=jpeg "")  
  
  
  
  
**·****今 日 推 荐**  
**·**  
  
> 《速学Python:程序设计从入门到进阶》面向没有任何编程基础的初学者。全书共9章，第1、2童以尽可能少的幅，完成了对编程环境的搭建、编程的基本概念、Python语法、数据结构、面向对象编程技巧的讲述，这一部分内容虽然简单，但它对初学者非常重要，只有完成这一部分内容的学习，才能够继续深入。第3~6童是对第1、2章内容的深入与补充，主要是搭建更好的开发环境，更详细地讲述数据结构与函数，并通过编写一个计算器程序，深入了解解释器的基本工作原理以及面向对象编程。第7~9童讲述了如何创建程序的可视化界面，将Pvthon程序打包为可执行程序并使用主流数据库进行数据存储，继而实现数据分析与数据图表的生成。  
  
  
  
  
