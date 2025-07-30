#  漏洞挖掘小工具 - SeeMore   
Bbdolt  网络安全者   2025-05-14 16:00  
  
暗月渗透测试13 社工篇7课合集下载  
  
链接：https://pan.quark.cn/s/1823fbf3e490  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccxdOvXt6Ez07aIM7LibibYn72pBSiaVQKwmvibhib5crLpibzgr09CG7HHLibrYaNkziaFq0tQAfaiabqkciaZQ/640?wx_fmt=png&from=appmsg "")  
  
===================================  
免责声明请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。个人微信：ivu123ivu  
0x01 工具介绍  
在某系统中发现导入文件功能存在注入攻击提交修复后，程序员只是将导入的元素添加"display: none;"隐藏起来了， 但是这个功能还是存在，所以可以通过将"display: none;"删除达到显示导入功能（二次绕过）。这里在提供一思路，在第 三次修复后，程序员可能只是将页面对应的代码段删除，但是后端的api仍然存在，可以利用之前的数据包（可能需要修改Cookie） 进行重放攻击。但是如果每次都要去手动修改不可见元素为可见就太麻烦了还可能错过一些可利用的功能点，所以就做了这 个插件可以显示隐藏的可点击（重点）元素不会将一些无用的文本弹窗等显示出来造成页面的不美观，下面讲讲这个插件的 应用场景以及安装方法。  
0x02 安装与使用  
1、这里以Webgoat靶场为例   
  
![PixPin_2025-03-01_19-58-08](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccxdOvXt6Ez07aIM7LibibYn72YZ7F2xwpliaNsMmlsBibGHu1zmkKRoOArVsXVBFuZ5iaXgusKXF8trQhA/640?wx_fmt=png&from=appmsg "")  
  
 2、点击 Show Hidden 即可，显示出隐藏的按钮。点击 recover 即可恢复之前的页面。   
  
![PixPin_2025-03-01_20-00-28](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccxdOvXt6Ez07aIM7LibibYn72yicmeXmO7Cy8icSFtIebn1czbY2rthEWVickLpejUhsJFfCFCoibsb4W0g/640?wx_fmt=png&from=appmsg "")  
  
 3、安装教程，Google 打开 chrome://extensions/ 链接，开启开发者模式，点击"加载以解压的扩展程序"，选择下载解压后的文件夹导入即可。   
  
![PixPin_2025-03-01_20-02-55](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccxdOvXt6Ez07aIM7LibibYn72TLE0O8D3OXM35lr1hlUArVMzTlG4BcREhibfgmwOeDKUzupjq2nXMVw/640?wx_fmt=png&from=appmsg "")  
  
   
  
![PixPin_2025-03-01_20-03-24](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccxdOvXt6Ez07aIM7LibibYn72RBR23JV19EdQWtEF9UhbfQNmAtJwHHGszdy81kNNV4CHLqjNODwQnw/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
**·****今 日 推 荐**  
**·**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/0JJXjA8siccxdOvXt6Ez07aIM7LibibYn72xDdQRRmiaHEcwp9ITScZkVHpjKib6iasJ79bHLHFUDJuPrDjiasCrWcORQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
