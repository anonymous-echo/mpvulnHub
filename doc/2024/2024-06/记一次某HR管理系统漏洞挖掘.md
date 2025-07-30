#  记一次某HR管理系统漏洞挖掘   
原创 mkbk  小黑说安全   2024-06-05 18:22  
  
## 0x01 前言  
##   
  
某次审计过程记录，也是比较常见的一个系统，懂得都懂。  
## 0x02 分析与利用       
  
**权限绕过：**  
  
通过关键字关联到过滤器。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8OB0HFWzksGMZgoFWaxB2qLABomoSvI8ar8xFJTmsUZuVArhicc3hejcuUHH9iaFlQicqbBCcRnUYq1Q/640?wx_fmt=png&from=appmsg "")  
  
通过之前黑哥文章中提到的jar包定位工具，定位存在于哪个jar包，这里也贴一下代码吧。  
```
import os
import zipfile
import sys

# 确保有足够的命令行参数传入
if len(sys.argv) < 3:
    print("Usage: python tqu.py <directory_to_search> <text_to_search>")
    sys.exit(1)

# 第一个命令行参数是要搜索的目录
directory_to_search = sys.argv[1]
# 第二个命令行参数是要搜索的文本
text_to_search = sys.argv[2]

# 遍历目录
for foldername, subfolders, filenames in os.walk(directory_to_search):
    for filename in filenames:
        if filename.endswith('.jar'):
            # 构造完整的文件路径
            full_path = os.path.join(foldername, filename)
            try:
                # 打开JAR文件
                with zipfile.ZipFile(full_path, 'r') as jarfile:
                    # 遍历JAR文件内的每个文件
                    for name in jarfile.namelist():
                        # 打开JAR文件内的文件
                        with jarfile.open(name) as file:
                            if text_to_search.encode() in file.read():
                                print(f"Found '{text_to_search}' in {full_path}")
                                break  # 找到文本后跳出循环
            except zipfile.BadZipFile:
                print(f"Bad zip file: {full_path}")
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8OB0HFWzksGMZgoFWaxB2qL2aDPvMzAYRWAKSJ6N8wJqhf4fVCCckIAYtohlDviaD753nKDD5bKpEA/640?wx_fmt=png&from=appmsg "")  
  
这里  
请看图  
注释  
。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8OB0HFWzksGMZgoFWaxB2qLd60YB1ZibwlLd5kibMzBUDHZtOcSrzUuIDd3QmVKqxRagVDMnQ9SrnbA/640?wx_fmt=png&from=appmsg "")  
  
满足框选中的  
任一  
路径  
接  
../即可，使其为false。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8OB0HFWzksGMZgoFWaxB2qLx8dibYMFCWn6iagibU1VVoK6hQoUnSct7kGNSj4L1eIdJUtj2Kl9AMEuQ/640?wx_fmt=png&from=appmsg "")  
  
满足框选中的  
任一  
路径  
接  
../即可，使其取反后为false。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8OB0HFWzksGMZgoFWaxB2qLRkxSuVvmOGUy46zfjAMl99sQVxeFdrMPwpN9dJgBPxQSZfBzPz9qXg/640?wx_fmt=png&from=appmsg "")  
  
**文件上传：**  
  
一样搜索上传相关关键字。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8OB0HFWzksGMZgoFWaxB2qLl3uHxmO5aqqJemicu2ic63VweY3wTnjCXJ0ptNVhSFYQjfEOKyUibHtWg/640?wx_fmt=png&from=appmsg "")  
  
在进入大if之前，这里需要满足  
safariORFo  
xType不为空，  
内  
容加密后大于8且为true  
，以及时间不  
为空且  
d  
atams参数  
的内容  
要满足  
减  
当前时间后  
<  
=120000L。  
  
  
这里进来第一眼看到一个绝对路径的文件删除。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8OB0HFWzksGMZgoFWaxB2qLu2xAvfVPOMH5a5qq3qibTQbbDhB80FfTbX9dXicn8SialAiaFJNDghbQYw/640?wx_fmt=png&from=appmsg "")  
  
构造请求包复现，成功删除。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8OB0HFWzksGMZgoFWaxB2qL0eXYS2NsJL5wnvfqIPWtDQQ9fNHRFDXqtIjA283K8mSovLWnbqBuKA/640?wx_fmt=png&from=appmsg "")  
  
继续往下按走当down不为true时，会走进下面大else进入上传逻辑。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8OB0HFWzksGMZgoFWaxB2qLjuW70YibZGAUtSJ9Y2AibAibQFrS8VNXloXcVUPicuqz4SW8icUzeuKvc6w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8NKZib9H5qkKYicUX6TS1c6p0KVvsCUFBzCRH6JwhklAoYic5zzVWayiabgOwia37AJgPaia8TapjzmOB6Q/640?wx_fmt=png&from=appmsg "")  
  
new file相关参数，以及上传内容以及后缀均可控。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8OB0HFWzksGMZgoFWaxB2qLFdk3icOeyOVWfVVrhkY1alETiapEdkqzVNqj5LMefpr9ibSjjyicSYyialQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8OB0HFWzksGMZgoFWaxB2qLlSlibLkWa8QNUCE2Z1Z3CqwDdeRJDibfD9DmVbGkGicQBteItj9hbNCrA/640?wx_fmt=png&from=appmsg "")  
  
但有个问题，是需要绝对路径写入的，但这里恰好就泄露了网站路径。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8OB0HFWzksGMZgoFWaxB2qLetcZhA81mF4v0bmbibh8rv06M91zGJq8phywTJB588jib47AAQ4R9Iibg/640?wx_fmt=png&from=appmsg "")  
  
构造请求包复现，成功上传。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8NKZib9H5qkKYicUX6TS1c6p0WNjF0Wibb7nCGTpWMFlBoqqOUoeKmavhszDniaa7PYZWdtdnN60HL35A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8NKZib9H5qkKYicUX6TS1c6p0H31wHDqqo2w2hibPoB0f6u2KpibK1MJKxvffgWalupkO30qBxHdAZOJg/640?wx_fmt=png&from=appmsg "")  
## 0x03 小密圈‍‍‍‍‍‍‍‍  
## 最后送你一张优惠券，欢迎加入小密圈，好朋友。  
##   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/9zZrDr2DM8OB0HFWzksGMZgoFWaxB2qLJ5bybhKXKp0JDvSQO7weZyB9ynibGeMvIaEFD9iaNjO5HOwhWo7pBZng/640?wx_fmt=jpeg&from=appmsg "")  
  
