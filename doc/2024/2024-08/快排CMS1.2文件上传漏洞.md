#  快排CMS1.2文件上传漏洞   
 菜鸟小新   2024-08-16 11:58  
  
侵权声明  
  
本文章中的所有内容（包括但不限于文字、图像和其他媒体）仅供教育和参考目的。如果在本文章中使用了任何受版权保护的材料，我们满怀敬意地承认该内容的版权归原作者所有。  
  
感谢您的理解与支持  
> **靶场安装地址：/index.php/install**  
  
### 漏洞成因：  
  
对文件后缀逻辑判断不当，当上传文件后缀为php时，该in_array($extension, ['gif', 'jpg', 'jpeg', 'bmp', 'png', 'swf'])判断会返回false就不会继续执行后面的语句返回true。因该加一个取反。  
```
if (in_array($extension, ['gif', 'jpg', 'jpeg', 'bmp', 'png', 'swf']) && !in_array($this->getImageType($this->filename), [1, 2, 3, 4, 6, 13]))

```  
  
#### 漏洞的位置  
  
漏洞地址：/admin.php/post/add/cid/5.html/admin.php/config/index.html/admin.php/banner/edit/id/1.html漏洞代码位置：thinkphp/library/think/File.php的267行方法  
#### 分析：  
  
下面是检查文件上传的主要验证代码，因为rule数组是空的没有被定义，所以只有红框处的函数起作用即检查文件后缀是否为图片的函数。可能在实际生成环境中rule会被定义完整。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rgHsQiafgQShXbwY2icsL2glnRicam0hzM5BCZIlwLcmbUWaWPv179dhvWd7Wz9EOCJxicYuwMw0VJEKeWAUeNLUfA/640?wx_fmt=png&from=appmsg "")  
  
跟进checkImg()函数即可以啊看到红框处就前一个是验证后缀  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rgHsQiafgQShXbwY2icsL2glnRicam0hzM5QNWFdWIcGHV99L2AvOp92ic0ItnibbfdsOXfvc58Y2icucicfX5ZXDwAZA/640?wx_fmt=png&from=appmsg "")  
  
后一个判断跟进发现是判断常见类型图片的基本信息如：长宽，因为第一个判断的函数不存在所以是直接判断图片的基本信息了。因为第一个判断已经是false了并且两个判断的关系是与，所以该判断是不会执行的，**不过该函数应该可以通过制作图片马进行绕过，我试了一下我现在制作的图片马绕不过去。(如有不对请指出)**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rgHsQiafgQShXbwY2icsL2glnRicam0hzM5UBMMwxx5Ss0j7Ax9ibqKokagR4MKAyGGWbMm4icccvgSzh4gKfjCwxsA/640?wx_fmt=png&from=appmsg "")  
  
发现有意思的如果你文件上传成功后网址不仅会返回文件保存地址还会去访问一次你上次的文件，可以用bp看到这现象  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rgHsQiafgQShXbwY2icsL2glnRicam0hzM5hz7ewu4jTAmt8DoJCqS6PVl4cn9mlj6JEyQCyIgO0YX1zuAtc3mE6A/640?wx_fmt=png&from=appmsg "")  
  
### 复现：  
  
1、找文件上传位置，点击管理 -> 文章管理 -> 发布  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rgHsQiafgQShXbwY2icsL2glnRicam0hzM5M8foRcgXeDUNiaHcznnxIglRAUqlWib3rRMgdpWRHFn5Bm31VFAY2KQA/640?wx_fmt=png&from=appmsg "")  
  
2、一句话或其他利用文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rgHsQiafgQShXbwY2icsL2glnRicam0hzM5N85F0mOdJWnXTuwY2EyTtKhdq1LzsMoOTP9enmCOcJbibLCBoLNZ2mg/640?wx_fmt=png&from=appmsg "")  
  
3、成功上传  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rgHsQiafgQShXbwY2icsL2glnRicam0hzM5ZWyQbDibUNGljticqZjTbejy7CuibQDzWIOv05Yt0rkgMHFMlFXFibZlXA/640?wx_fmt=png&from=appmsg "")  
  
4、成功访问  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rgHsQiafgQShXbwY2icsL2glnRicam0hzM57tGSicyuUiajBblD6E8C0bs6VSEChKmibUq67C6kA4dmjVna78WHfxNFA/640?wx_fmt=png&from=appmsg "")  
  
### 总结  
  
代码逻辑问题，形成了漏洞。  
### 参考  
  
https://blog.csdn.net/weixin_52635170/article/details/126950674https://github.com/wgpsec/peiqi-wiki/blob/master/PeiQi_Wiki/CMS%E6%BC%8F%E6%B4%9E/%E5%BF%AB%E6%8E%92CMS/%E5%BF%AB%E6%8E%92CMS%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E4%B8%8A%E4%BC%A0%E6%BC%8F%E6%B4%9E.md  
  
  
