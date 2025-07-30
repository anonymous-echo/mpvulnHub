#  SeeMore！一个漏洞挖掘小工具   
 黑白之道   2025-04-20 11:35  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
**工具介绍**  
  
1、在某系统发现在导入文件时，文件内容没有进行过滤导致存储型xss注入，可以发送任何人或提交模板（管理员会审查）危害挺大的，然后提交漏洞后他进行了修复。  
  
2、但是  
程序员只是将导入功能的元素添加"display: none;"隐藏起来了， 但是这个功能还是存在，所以可以通过将"display: none;"删除达到显示导入功能（二次绕过）。  
  
3、这里再提供一思路，在第2次修复后，程序员可能只是将页面对应的代码段删除，但是后端的api仍然存在，可以利用之前的数据包（可能需要修改Cookie） 进行重放攻击。  
  
但是如果每次都要去手动修改不可见元素为可见就太麻烦了，还可能错过一些可利用的功能点，所以就做了这个插件可以显示隐藏的可点击（重点）元素，不会将一些无用的文本弹窗等显示出来造成页面的不美观，下面讲讲这个插件的应用场景以及安装方法。  
  
如果大家在使用过程中遇到了bug或一些没有成功显示的元素，可以提交到issues中，我会尽快完善匹配规则，感谢大家支持。  
  
  
**工具使用**  
  
1、这里以Webgoat靶场为例  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/79gZQNibQ6ucZmnEM4ic7BNGMGr4B0qcmNhbDOc1b99mYjw90uMW2OaJsL6X6cL4uDdVXVicicTLwmaRIOECQOAkIA/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
2、点击 Show Hidden 即可，显示出隐藏的按钮。点击 recover 即可恢复之前的页面。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/79gZQNibQ6ucZmnEM4ic7BNGMGr4B0qcmNTgnf59sbJlIAXibH3SPytEj38RZDibm42F99rmTmXbRtwHPlT8AhvptQ/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
3、安装教程，Google 打开 chrome://extensions/ 链接，开启开发者模式，点击"加载以解压的扩展程序"，选择下载解压后的文件夹导入即可。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/79gZQNibQ6ucZmnEM4ic7BNGMGr4B0qcmNGhJjqvLrlSASb0AFdcn5abLTOhGU5XEf8jk1vzY0mYWDtDDTRAgj2g/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/79gZQNibQ6ucZmnEM4ic7BNGMGr4B0qcmN4FH9JSlt9yx5B4ibJLEEAppoWYPiaROibAzI5ptIurN9dLlEmX12qx5ag/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
#### V1.0.1更新  
  
1、添加显示通过 <!-- 注释隐藏起来的可点击内容，这个页面存在隐藏的功能框  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/79gZQNibQ6ucZmnEM4ic7BNGMGr4B0qcmN2Lgs4uGRID0XVice2Lic4VyPwDxXVANmQT1660mHr0vCvMrDfOq7eLcw/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
2、点击 Show Hidden 显示功能  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/79gZQNibQ6ucZmnEM4ic7BNGMGr4B0qcmNb0Ekhtz3jtxWprmpMbCDb9z48bHqKGygnXnh8Mp9MVf2cbPPPllDCQ/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
#### v1.0.2更新  
#### 修复部分bug（注释功能）  
  
#### 案例补充  
  
发现上传功能，可以上传任意后缀但是对于大多数文件不解析，但可以解析html文件  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/79gZQNibQ6ucZmnEM4ic7BNGMGr4B0qcmNcmibAZgd6PdH8ZJUgkDL5GVeXjlUwJWwRQ06YXjPZ3HUBGR1LLyODmA/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**下载地址**  
  
**https://github.com/Bbdolt/SeeMore**  
  
  
> **文章来源：Hack分享吧**  
  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  
