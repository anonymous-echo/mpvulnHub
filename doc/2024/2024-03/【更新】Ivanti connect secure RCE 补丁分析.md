#  【更新】Ivanti connect secure RCE 补丁分析   
原创 chestnut  闲聊趣说   2024-03-27 15:21  
  
接前文  
  
[CVE-2023-46805&CVE-2024-21887 Ivanti connect secure RCE分析](http://mp.weixin.qq.com/s?__biz=MzIwODc2NjgxNA==&mid=2247483998&idx=1&sn=458260eabdb4ebe9e3c9d30dfd288ee4&chksm=977f506fa008d979f941328ab85b69cebef494aeb5fc33728e7b4f1962d6a7ca72b7c795c001&scene=21#wechat_redirect)  
  
  
之前由于没有弄到补丁，现在补充一下补丁分析。  
#### 补丁分析  
  
安装补丁后，按照老办法将磁盘密钥拖出来，而后解密磁盘，得到修复后的代码。  
  
**目录穿越**  
  
查看diff可知修改了如下函数  
  
![](https://mmbiz.qpic.cn/mmbiz_png/M3XUNBmia1tMDyBLMECYfHbichLXViabLRVmYXBlcbBatNhUAHJ2Naiarq4acmdr7DsRqvJzXffOmPYvdicypjXtoTw/640?wx_fmt=png&from=appmsg "")  
  
查看代码后可知，在PyRestHandler:WebHandler  
函数中对目录穿越漏洞进行了修复，在web服务器将请求转发给restservice之前，先验证了url中是否有../及各种变形，验证通过后才将请求转发给后端的restservice。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/M3XUNBmia1tMDyBLMECYfHbichLXViabLRVscyVrqEqHUDUN5Qa2UicDTsa88HF4GRwRtq02XqB2Y0m3iaiaf1cEnSCw/640?wx_fmt=png&from=appmsg "")  
  
****  
**命令执行**  
  
从补丁中可以看到其将Popen的stdout改为了subprocess.PIPE，从而将命令执行修复。  
```
    
```  
```
def get(self, url_suffix=None, node_name=None):
        if request.path.startswith("/api/v1/license/keys-status"):
            try:
                dsinstall = os.environ.get("DSINSTALL")
                if node_name == None:
                    node_name = ""
                else:
                   ....
                proc = subprocess.Popen(
                    [
                        dsinstall + "/perl5/bin/perl",
                        dsinstall + "/perl/getLicenseCapacity.pl",
                        "getLicenseKeys",
                        node_name,
                    ],
                    stdout=subprocess.PIPE,
                )
```  
```

```  
  
  
同样的在awsazuretestconnection.py中也对命令注入进行了修复  
```

```  
```
                    args = [
                        dsinstall + "/perl5/bin/perl",
                        dsinstall + "/perl/AwsAzureTestConnection.pl",
                        method,
                    ]
                    args.extend([str(x) for x in server_information])
                    proc = subprocess.Popen(
                        args,
                        shell=False,
                        stdout=subprocess.PIPE,
                    )
                    output, errors = proc.communicate()
```  
```

```  
  
  
