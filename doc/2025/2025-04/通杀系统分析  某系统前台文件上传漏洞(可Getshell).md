#  通杀系统分析 | 某系统前台文件上传漏洞(可Getshell)   
原创 匿名白帽子  WK安全   2025-04-20 00:31  
  
```
免责声明
  由于传播、利用WK安全所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负
责，WK安全及作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除
并致歉。谢谢！
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ljib4So7yuWhyISs8bEe5qrWLOocUeBq1uYPAHehHO8tQyibepiaWJD2KvcsEfaWcrvW6tRMs7wELCJyT1GznvGHA/640?wx_fmt=png&from=appmsg "")  
  
**背景**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ljib4So7yuWhyISs8bEe5qrWLOocUeBq1W9t1SgFGIdN85bxvOZ9pKrjhdcXtB34s13Rb9ZlpmynGtq5SmopbXw/640?wx_fmt=png&from=appmsg "")  
  
  
本次系统的审计挖掘过程，借助了阿呆安全的审计辅助插件  
CodeAuditAssistant  
  
项目地址我贴在了文末，如果不想下载的，可以直接后台回复"  
插件  
"获取，我也是第一次使用也是借助这个插件快速出货了，文章如有分析不当的地方，欢迎斧正！（漏洞还未上交相关平台，厚码勿怪！）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1qkgPBQslIFHcGsAQ5gy1YwYjnRgFibWfmKnVp5SkImALGoGibqZGKtzTEsmcT8oEXtP80CXy7sNiaGQkQrtrficiaw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ljib4So7yuWhyISs8bEe5qrWLOocUeBq1uYPAHehHO8tQyibepiaWJD2KvcsEfaWcrvW6tRMs7wELCJyT1GznvGHA/640?wx_fmt=png&from=appmsg "")  
  
**挖掘过程**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ljib4So7yuWhyISs8bEe5qrWLOocUeBq1W9t1SgFGIdN85bxvOZ9pKrjhdcXtB34s13Rb9ZlpmynGtq5SmopbXw/640?wx_fmt=png&from=appmsg "")  
  
  
  
    拿到该源码之后，查看下项目结构，经典的Jsp+Servlet，路由访问是通过注解实现的，然后登录认证部分采用的是Shiro，既然是使用Shiro，肯定先查看排除认证部分的路由啦！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1qkgPBQslIFHcGsAQ5gy1YwYjnRgFibWfU8nwY8P1MG2naS56JAJNMY9RfxdSpRmwzM2iadvhrxdOibDicYaibyibBww/640?wx_fmt=png&from=appmsg "")  
  
从文件名搜索：shiro  
  
从内容搜索：anon (如果是class文件，建议先进行反编译再搜索)  
  
经过搜索，也是成功定位到了配置文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1qkgPBQslIFHcGsAQ5gy1YwYjnRgFibWf6ZzDPbXB8pVNCbWJ2QvSnbib9LHDTKgyeqs7yycrtoQUiazw3rI0miaXA/640?wx_fmt=png&from=appmsg "")  
  
这个系统的代码量、功能点也是蛮多的，anon对应的路径也非常多，一个一个看的话太耗时间，直接上插件  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1qkgPBQslIFHcGsAQ5gy1YwYjnRgFibWfMVWa3UEBe4PSXHQaYtPPSWicvzia3m9tJvgopZ2aSHo2iasWPftdqnIGA/640?wx_fmt=png&from=appmsg "")  
  
  
快速定位了几个漏洞点(sink)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1qkgPBQslIFHcGsAQ5gy1YwYjnRgFibWfTqDGQiaibn98nRNyBWKFjEpNeqmUOSCTibLVNY7HDiaSmB6icicKicYWJJMOA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ljib4So7yuWhyISs8bEe5qrWLOocUeBq1uYPAHehHO8tQyibepiaWJD2KvcsEfaWcrvW6tRMs7wELCJyT1GznvGHA/640?wx_fmt=png&from=appmsg "")  
  
文件上传  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ljib4So7yuWhyISs8bEe5qrWLOocUeBq1W9t1SgFGIdN85bxvOZ9pKrjhdcXtB34s13Rb9ZlpmynGtq5SmopbXw/640?wx_fmt=png&from=appmsg "")  
  
  
结合扫描出的漏洞点，我们再结合刚才shiro的排除认证的路由，定位到了一处  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1qkgPBQslIFHcGsAQ5gy1YwYjnRgFibWfviaSo7Lby7FwMY0UuIEb8IAvjceDy3xH6ib9ofEmGBFQc4yWJhnegaEg/640?wx_fmt=png&from=appmsg "")  
  
这个控制器实现的功能就一个，处理(批量)文件上传的功能  
```
for(int var10 = 0; var10 < var9; ++var10) {    
MultipartFile file = var8[var10];    
String fileName = file.getOriginalFilename();    
String suffix = fileName.substring(fileName.lastIndexOf("."));    
int num = (int)(Math.random() * 1000.0);    
String fileNewName = fileName.substring(0, fileName.lastIndexOf(".")) + "_" + num + suffix.toLowerCase();    
String dataFormat = (new SimpleDateFormat("yyyyMMdd")).format(new Date());    
String savePath = uploadPath + File.separator + dir + File.separator + dataFormat + File.separator + "lab_report";    
File destDir = new File(savePath);    if (!destDir.exists() || !destDir.isDirectory()) {        destDir.mkdirs();    }    File f;    for(f = new File(savePath + File.separator + fileNewName); f.exists(); f = new File(savePath + File.separator + fileNewName)) {        num = (int)(Math.random() * 1000.0);        fileNewName = fileName.substring(0, fileName.lastIndexOf(".")) + "_" + num + suffix;    }    file.transferTo(f);
```  
  
设置上传的路径  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1qkgPBQslIFHcGsAQ5gy1YwYjnRgFibWfwl9Hia62xQibD0l6fGYJKw7TWzEY4dcaiavdCu3vNyf6ahibSvhQ0Nhy0Q/640?wx_fmt=png&from=appmsg "")  
  
设置个新的文件名  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1qkgPBQslIFHcGsAQ5gy1YwYjnRgFibWfiblS1tzXtLI3ibe9GafMXVINLSM975cvfymjygARf2uNETZe4iaI6RicsQ/640?wx_fmt=png&from=appmsg "")  
  
然后调用  
```
file.transferTo(f);
```  
  
进行上传  
  
构造数据包发起请求  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1qkgPBQslIFHcGsAQ5gy1YwYjnRgFibWfSTiaAstZu1ED4u6Mou44ibnodGGLkTJEGTwBmHZj0jdTrwhRnXDV3X2A/640?wx_fmt=png&from=appmsg "")  
  
访问上传文件，成功解析  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1qkgPBQslIFHcGsAQ5gy1YwYjnRgFibWfhH2zL6tiaIQ6xhmhK4R5udqM3gKIg5FmHhgqibuLicfuU0hPKMjX3sOHw/640?wx_fmt=png&from=appmsg "")  
  
插件项目地址：  
```
https://github.com/springkill
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ljib4So7yuWhyISs8bEe5qrWLOocUeBq1uYPAHehHO8tQyibepiaWJD2KvcsEfaWcrvW6tRMs7wELCJyT1GznvGHA/640?wx_fmt=png&from=appmsg "")  
  
**安全交流**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ljib4So7yuWhyISs8bEe5qrWLOocUeBq1W9t1SgFGIdN85bxvOZ9pKrjhdcXtB34s13Rb9ZlpmynGtq5SmopbXw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1qkgPBQslIE86rkUF75rwvvt9uKTxvvogJRoL8yBnopD66HwrzyNl1r8yxniaR9ndxkib97TSRktMHh8nyr71LKw/640?wx_fmt=jpeg&from=appmsg "")  
  
