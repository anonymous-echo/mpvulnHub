#  jsmug：一个针对JSON Smuggling技术的测试PoC环境   
Alpha_h4ck  FreeBuf   2024-05-30 18:57  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
jsmug是一个代码简单但功能强大的JSON Smuggling技术环境PoC，该工具可以帮助广大研究人员深入学习和理解JSON Smuggling技术，并辅助提升Web应用程序的安全性。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ib9MJ15qcLJFfk52icfyaG8iaFthO33WGBI4aXeib4d8X9QoAfW0NsagpMKkfIMNNyibayiarylNrhqC8Q/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**背景内容**  
  
  
##   
  
JSON Smuggling技术可以利用目标JSON文档中一些「不重要」的字节数据实现任意文件传输。根据JSON文档的官方定义，JSON文件中的某些位置允许使用被称为不重要字节的字节数据来传输内容。这些所谓不重要的字节在JSON文档中没有任何的意义，因此会被jq之类的JSON解析工具直接忽略。这种「不重要」的字节包括：  
  
> 0x09（水平制表符）  
> 0x0a（新行）  
> 0x0d（回车）  
> 0x20（空格）  
  
  
  
这些字节本身就不起眼，甚至根本就不是肉眼可见的，而且JSON解析器也会直接忽略这些字节，因此这4个字节可以用来编码任意数据或文件。与我们使用Base2系统以二进制格式表示数据相同，我们可以使用Base4系统使用这4个字节来表示数据：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ib9MJ15qcLJFfk52icfyaG8iaMM7KUj74CrakWjxhToGn859aEsoTLEm6onjQtoKVnHdNfiaOUsZdHug/640?wx_fmt=jpeg&from=appmsg "")  
  
  
上图中的数据显示了原始字节是如何以Base4表示的，接下来这些Base4字节被映射到它们各自的「不重要字节」的部分。根据指定的bytes_per_pair，Base4符号字节会被成对划分，并存放到JSON文档中的指定位置。通过指定应该存放在一起的字节数据的数量，我们还可以用其来测试网络安全检测规则的有效性。  
  
  
**工具下载&编译**  
  
  
##   
  
由于该工具基于纯C语言开发，因此我们首先需要在本地设备上暗安装并配置好C语言环境，或直接安装gcc编译器。  
  
  
接下来，广大研究人员可以直接使用下列命令将该项目源码克隆至本地：  
```
git clone https://github.com/xscorp/jsmug.git
```  
  
  
然后切换到项目目录中，使用gcc编译器完成代码编译：  
```
$ cd jsmug

$ gcc jsmug.c -o ./jsmug
```  
  
**工具使用**  
  
  
##   
### 编码文件  
  
  
我们可以使用下列密令对一个输入文件进行编码，并将编码后的结果输出保存到另一个文件中：  
```
$ ./jsmug encode <input_file_name> <output_file_name> <bytes_per_pair>
```  
  
  
在下面的代码示例中，我们将naabu代码编码进了一个JSON文件中，输出文件名称为「sweet-document.json」：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ib9MJ15qcLJFfk52icfyaG8iaicQIcNsnzS2zWaZpsBoUdgenRQ9cBQGITbYeXY4qkguibvxylewVAB8Q/640?wx_fmt=jpeg&from=appmsg "")  
  
### 解码文件  
  
  
我们可以使用下列命令对一个已编码的文件进行解码，并将输出的结果保存到另一个文件中：  
```
$ ./jsmug decode <encoded_file_name> <output_file_name>
```  
  
**使用演示：**  
```
$ ./jsmug decode ./encoded-binary.json decoded-binary
```  
  
在下面的代码示例中，我们对之前生成的「sweet-document.json」JSON文件进行解码，并获取原始的naabu代码，然后将其标识为「decoded-binary」：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ib9MJ15qcLJFfk52icfyaG8iaMH51lTtMbnzUCIPlBCdEHamBmuASOTOZt8zfS3jVEnPKIbVHEbuvgw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**项目地址**  
  
  
##   
  
**jsmug：**  
  
https://github.com/xscorp/jsmug  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊  
】  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ61icYlLmBLDpdYEZ7nIzpGovpHjtxITB6ibiaC3R5hoibVkQsVLQfdK57w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
> https://datatracker.ietf.org/doc/html/rfc8259#section-2  
> https://grimminck.medium.com/  
> https://grimminck.medium.com/json-smuggling-a-far-fetched-intrusion-detection-evasion-technique-51ed8f5ee05f  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247493836&idx=1&sn=618ec2e0ea830222e8c14ea4c912ef27&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247493767&idx=1&sn=9b3400e4901e706ab29b1df75b4906fa&chksm=ce1f1218f9689b0e58e78c64d26531983b65daede2e93dbecd43d4b134cae1212d4fa69cf29b&scene=21#wechat_redirect)  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
