#  漏洞挖掘小工具 -- SeeMore（3月1日更新）   
Bbdolt  Web安全工具库   2025-03-01 16:00  
  
===================================  
免责声明请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。个人微信：ivu123ivu  
0x01 工具介绍  
在某系统发现在导入文件时，文件内容没有进行过滤导致存储型xss注入，可以发送任何人或提交模板（管理员会审查）危害挺大的。 然后提交漏洞后他进行了修复，但是只是将导入功能的元素给隐藏了功能还在（接口），可以F12修改显示然后又是一次绕过，但是 每次手动修改太麻烦了，而且如果对于不熟悉的系统就需要一个个去找被隐藏的元素（出现几率小，工作量大），所以就做了一个自 动识别隐藏的可点击元素并显示出来，而且文件导入只是一个利用点，还有其他可能被隐藏起来危险功能点。  
0x02 安装与使用  
1、这里以webgoat为例，这里的Admin下拉框被隐藏起来了   
![PixPin_2025-03-01_19-58-08](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3Uibs5xvJzKdib3tCjLPiaIQBpmXiaWyNSovicP3UTsqte0XXo63jIRU8rvPMPxL44JQj1yNwHV1Z63kkFdg/640?wx_fmt=png&from=appmsg "")  
  
 2、点击Show Hidden，可以显示被隐藏的可点击元素，再次点击可以恢复回去   
![PixPin_2025-03-01_20-00-28](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3Uibs5xvJzKdib3tCjLPiaIQBpmXFb1Gr966Lt7mrJasnKRCuyGN97zlzS6G4PTUf6lWT5ibSNDngjicNn7A/640?wx_fmt=png&from=appmsg "")  
  
 3、导入插件教程   
![PixPin_2025-03-01_20-02-55](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3Uibs5xvJzKdib3tCjLPiaIQBpmXU3Rx5sPMoenZrV8MIQfGmB6gavlZH8HYeb2Yw9ur01ZxQdqYgVYNxQ/640?wx_fmt=png&from=appmsg "")  
  
   
![PixPin_2025-03-01_20-03-24](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3Uibs5xvJzKdib3tCjLPiaIQBpmXKSV2sib0wUAj3OQg5lJEQ0zslpXRI9SO9AM7JTLxiat8ShZmbeibZgjhw/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
**·****今 日 推 荐**  
**·**  
  
> 本书主要介绍了反爬虫的相关技术，内容涵盖了爬虫工具、加密算法、App爬虫等，从理论到案例实践，深入浅出。本书详细讲解了常用的抓包工具、反爬虫机制、验证码识别、动态网页反爬虫、JavaScript文件处理。本书聚焦加密数据的破解、App应用爬虫以及破解方法、部署爬虫程序。对于以上内容，本书进行细分总结，将相关知识点都纳入其中，形成一套完整的体系。  
  
  
