#  pwnobd：一款针对OBD-II设备的漏洞分析与渗透测试工具   
Alpha_h4ck  FreeBuf   2024-12-31 10:59  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
**关于pwnobd**  
  
  
## pwnobd是一款针对OBD-II设备的漏洞分析与渗透测试工具，该工具基于纯Python开发，可以帮助广大研究人员对OBD-II设备执行安全分析。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38HhiaXTrdT6htRicEufibw4pUib3e2CME6GC4JcbdXwxrEI3G5YYFZLFCZib1o7RQzibMdCghlPibyzibKcQ/640?wx_fmt=jpeg&from=appmsg "")  
##   
  
**工具要求**  
  
  
> Python 3  
  
##   
  
**工具安装**  
  
  
##   
  
由于该工具基于Python 3开发，因此我们首先需要在本地设备上安装并配置好最新版本的Python 3环境。  
###   
### 源码获取  
  
  
广大研究人员可以直接使用下列命令将该项目源码克隆至本地：  
```
git clone https://github.com/Nnubes256/pwnobd.git
```  
  
然后切换到项目根目录中，初始化一个虚拟环境：  
```
cd pwnobd

python -m venv .env
```  
  
  
激活虚拟环境：  
```
source .env/bin/activate
```  
  
  
将项目以包的形式安装到虚拟环境中：  
```
pip install -e .
```  
###   
### pipx安装  
  
  
该软件打包为 Python 包，因此可以使用pipx在受控环境中快速安装该软件：  
```
pipx install git+https://github.com/Nnubes256/pwnobd.git
```  
  
  
安装后，使用以下命令运行软件：  
```
pwnobd
```  
  
  
用于help发现可用的命令。命令历史记录保存在~/.pwnobd_history中。  
##   
  
**工具使用**  
  
  
##   
### 渗透测试  
  
  
pwnobd的渗透测试脚本位于src/pwnobd/modules/attacks/目录中，渗透测试流程如下：  
> 1、def precheck(**kwargs)：每次为渗透测试设置选项时都会调用，允许实现超出OPTIONS提供的自定义参数验证；  
> 2、def __init__(self, arg1: type1, arg2: type2, ...)：发起渗透测试的第一步；获取我们在OPTIONS处指定的参数；  
> 3、async def setup(self)：渗透测试发起的第二步，在此进行初始化；  
> 4、async def run(self, ctx: WorkTaskContext, devices: dict[int, Device])：实际的渗透测试实施在此处，在任务内运行；  
  
###   
### 设备与扫描  
```
```  
```
class BluetoothThingymabobScanResult(ScannedDevice):

    # TODO implement

    #   name(self) -> str

    #   device_type(self) -> str

    #   create_device(self) -> Device

    pass

 

@scanner("thingymabob")

class BluetoothThingymabobScanner(LeafScanner):

    async def scan(self, ctx: ScanContext):

        # Retrieve `BluetoothScanner` and ask it to scan for Bluetooth devices.

        devices = await ctx.get_scanner(BluetoothScanner).scan(ctx)

 

        # ... do something with the returned devices...

 

        return [

          BluetoothThingymabobScanResult(...),

          BluetoothThingymabobScanResult(...),

          # ...

        ]
```  
```
```  
  
**许可证协议**  
  
  
##   
  
本项目的开发与发布遵循  
MIT  
开源许可协议。  
##   
  
**项目地址**  
  
  
##   
  
**pwnobd**：  
  
  
https://github.com/Nnubes256/pwnobd  
##   
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊】  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ic5icaZr7IGkVcd3DT6vXW4B4LOZ1M7YkTPhS1AT2DQJaicFjtCxt5BRO7p5AOJqvH3EJABCd0BFqYQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
