#  漏洞扫描工具 -- vulcat   
CLincat  黑客白帽子   2024-08-12 20:58  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJG3jJlPv0w6V8YUTyNSuV2udfyY3rWyR6V1UeHWuiab6T80I5ldZicZswCnrbicD4ibpaDMqCZ6UvFmhWLyTzptSA/640?wx_fmt=png&random=0.6636094571400317&random=0.6219011309810436&random=0.21191420540585404 "")  
  
**感谢师傅 · 关注我们**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJG3jJlPv0w6V8YUTyNSuV2udfyY3rWyR6V1UeHWuiab6T80I5ldZicZswCnrbicD4ibpaDMqCZ6UvFmhWLyTzptSA/640?wx_fmt=png&random=0.9829534454876507&random=0.2787622380037358&random=0.29583791053286834 "")  
  
  
由于，微信公众号推送机制改变，现在需要设置为星标才能收到推送消息。大家就动动发财小手设置一下呗！啾咪~~~  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJG3jJlPv0y50hQk1TiaBIAnSjzqkmZcPS4TWvohHfHPTVUBWM2mFxcqwhiaZKaQM6S7t11fuiajZ2zZqXD5hJJmA/640?wx_fmt=png "")  
  
  
0x01 工具介绍  
vulcat可用于扫描web端漏洞(框架、中间件、CMS等), 发现漏洞时会提示目标url和payload, 使用者可以根据提示对漏洞进行手工验证，使用者还可以自己编写POC, 并添加到vulcat中进行扫描, 本项目也欢迎大家贡献自己的POC。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8H1dCzib3UibuoCUVay0n3pJGoc2iczsHeKQfNjXThwVfviaxNBcicRqyGhDz9Mn7vxWNMrEpDoAbXUs5ePTgkpHwKw/640?wx_fmt=png&wxfrom=13&tp=wxpic "")  
  
  
  
0x02 安装与使用  
  
  
1、安装方法  
```
git clone https://github.com/CLincat/vulcat.git
cd vulcat
pip3 install -r requirements.txt -i https://mirrors.aliyun.com/pypi/simple
python3 vulcat.py -h
```  
  
2、常用命令  
```
Usage: python3 vulcat.py <options>
Examples:
python3 vulcat.py -u https://www.example.com/
python3 vulcat.py -u https://www.example.com/ -a thinkphp --log 3
python3 vulcat.py -u https://www.example.com/ -a tomcat -v CVE-2017-12615
python3 vulcat.py -f url.txt -t 10
python3 vulcat.py --list
```  
  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650939865&idx=1&sn=773462fd879df4c210ad316ed538483a&chksm=8bac6d26bcdbe4302b3b28dac2f62deaa16dc687bff0062a8ca5d90f6b124e3d2685544fdc03&scene=21#wechat_redirect)  
  
**下载地址**  
  
****  
https://drive.uc.cn/s/9e374fccebd04?public=1  
****  
  
  
**二个月前资源汇总**  
  
https://kdocs.cn/l/cq  
EYzWfs0kUS  
  
  
  
声明：本公众号所分享内容仅用于网安爱好者之间的技术讨论，禁止用于违法途径，**所有渗透都需获取授权**  
！否则需自行承担，本公众号及原作者不承担相应的后果  
```
```  
  
