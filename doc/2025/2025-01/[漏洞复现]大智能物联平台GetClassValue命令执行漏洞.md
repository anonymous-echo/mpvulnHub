#  [漏洞复现]大*智能物联平台GetClassValue命令执行漏洞   
原创 zzz  良月安全   2025-01-03 08:32  
  
## 免责声明  
  
本公众号所发布的所有内容，包括但不限于信息、工具、项目以及文章，均旨在提供学习与研究之用。所有工具安全性自测。如因此产生的一切不良后果与文章作者和本公众号无关。如有涉及公司与个人敏感信息，侵权烦请告知，我们会立即删除并致歉。  
  
## 漏洞分析  
  
漏洞挺简单的，直接用 Class.forName()  和 Method.invoke() 加载传入的类和调用方法。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/icm9yIBVk82gSSdiboMBOkjdicqtulkhpibWERAfWiaAn8I20ya0Ya3JAaoqCpbfrFDXR81ia9xQGh5k37Wsg64AHNPA/640?wx_fmt=jpeg&from=appmsg "")  
  
网上公开的 payload 是调用的 com.dahua.admin.util.RuntimeUtil 下的 syncexecReturnInputStream方法，能直接命令执行。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/icm9yIBVk82gSSdiboMBOkjdicqtulkhpibWxBYTpB61AkXgYCIiazWKicUaN4XoPnibJRr35HuibpDPGTyiaAvHYgGcHhA/640?wx_fmt=jpeg&from=appmsg "")  
  
## 漏洞复现  
  
关注微信公众号后台回复"  
**20250103**  
"获取 POC。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/icm9yIBVk82gSSdiboMBOkjdicqtulkhpibWmTADedrEUz253LvThI8VHUX0UCnNh7qZ0SslMdiciaWdv7v0t6nqOicTg/640?wx_fmt=jpeg&from=appmsg "")  
  
## 关于星球  
  
星球里有团队内部POC分享。星球定期更新安全内容，包括：内部漏洞库情报分享（包括部分未公开0/1day）、poc利用工具及内部最新研究成果。圈子目前价格为129元（交个朋友），后续人员加入数量多的话会考虑涨价（先到先得！！）感谢师傅们的支持！！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icm9yIBVk82jgcXGIvrTZZpzXJ1uibrCtRRn4yytlCGSsSfRZicib62GlHaz4ibXI8zWEvTuoW9G3e76BmaRBgvpy0Q/640?wx_fmt=png&from=appmsg "")  
  
