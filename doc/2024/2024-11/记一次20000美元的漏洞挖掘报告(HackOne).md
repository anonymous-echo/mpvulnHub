#  记一次20000美元的漏洞挖掘报告(HackOne)   
原创 Trangs  跃迁安全   2024-11-29 08:52  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/veqClViasOAEsZVL2J7IGzhP4tPP9s3qxROlFcnxFqEzojEv9IjSyp3UBu5SGa2BXumtYXXqlqwVSclU3XApRwQ/640?from=appmsg&wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9kDmnXgHicGGSXvO3NUGJDNeEzZobbHBXtL3bA6e6rGDwPV0xsEhXiaN2IePTSJGFKln0TMLvKcTOWvJGuOEHIVQ/640?from=appmsg&wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/O92iaayvHEgUtYiaKOTtXRd4BlicdLyV8vOuLicWpAcRNSBf6Pg8mibRUZUd1K5MTejcA2SQ3TplGMpGb4tPzXPdmog/640?from=appmsg&wx_fmt=png "")  
  
点击上方蓝字加入我们，感谢!!!  
  
![](https://mmbiz.qpic.cn/mmbiz_png/N4LgH3s3ZicCXw3EyK3YTCJrk33VxPV7gSCsFspgYprNNmk99vpFLNCVnWKpGWfjt2fYXxJn34yek6icLSbTT8WQ/640?from=appmsg&wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/LwD9AdX9DsHwo2r6ibwz8Z8zSqNribSqg8zMA2gswcj5cZPLIB8OHGvqqroiaU2WEefUv2N4T62W53TctjAeENMQw/640?from=appmsg&wx_fmt=png "")  
  
  
01  
  
![](https://mmbiz.qpic.cn/mmbiz_png/C5AX6CJJVUliaCP16NKtGQ4VCDb4w0oglEl3ziceJl4EFfMn5dy2wtvnoK6AWomP5WiaMFDr5LFOhyUTnKwQa13NQ/640?wx_fmt=png "")  
  
记一次20000美元的漏洞挖掘报告  
  
Enjoy life  
  
A HAPPY LIFE AFTER RAIN  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JzL1qjYyUjmfCKOCRhub9hO0adIAd4HYUCWsUFPkkJ6dK2NqOfKDbZiam7b22ZI99tH5rXQOrkUShlFdf8VveuA/640?wx_fmt=png&from=appmsg "")  
  
01  
  
漏洞点1：  
  
**“com.sony.gemstack.org.dvb.user.UserPreferenceManagerImpl”类使用不安全的“readObject（）”在特权上下文下反序列化“userprefs”文件：**  
  
```
private void initPreferences() {
      try {
        UserPreferenceManagerImpl.preferences = AccessController.doPrivileged((PrivilegedExceptionAction<String[][]>)new ReadPreferenceAction());
    }
    catch (PrivilegedActionException ex) {}
    if (UserPreferenceManagerImpl.preferences == null) {
        UserPreferenceManagerImpl.preferences = new String[UserPreferenceManagerImpl.PREFERENCES.length][];
    }
    if (UserPreferenceManagerImpl.preferences[3] == null) {
        UserPreferenceManagerImpl.preferences[3] = new String[] { "26" };
        this.savePreferences();
    }
}

```  
  
  
```
private static class ReadPreferenceAction implements PrivilegedExceptionAction{
     public Object run() throws Exception {
        String[][] array = null;
        ObjectInputStream objectInputStream = null;
        try {
            objectInputStream = new ObjectInputStream(new BufferedInputStream(new FileInputStream(RootCertManager.getOriginalPersistentRoot() + "/userprefs")));
            array = (String[][])objectInputStream.readObject();
        }
        finally {
            if (objectInputStream != null) {
                objectInputStream.close();
            }
        }
        return array;
    }}
```  
  
  
**攻击者可以将“userprefs”文件替换为恶意序列化对象，以 **实例化特权上下文下的类**。在不存在提交的较旧固件（如 5.05）上，很容易利用此漏洞：攻击者可以实例化 'ClassLoader' 子类以使用所有权限调用 'defineClass'，并最终绕过安全管理器。**  
  
02  
  
漏洞  
点2：  
  
**“com.oracle.security.Service”类包含一个方法“newInstance”，该方法对任意类名调用“Class.forName”。这允许实例化任意类，甚至是受限类（例如在 'sun.' 中）。这适用于具有单个参数的公共构造函数的所有类。可以通过在自定义 'ProviderAccessor' 实现上调用 'com.oracle.ProviderAdapter.setProviderAccessor' 来绕过 'newInstance' 中的检查。**  
  
```
if (!this.registered) {
    if (ProviderAdapter.getService(this.provider, this.type, this.algorithm) != this) {
        throw new NoSuchAlgorithmException("Service not registered with Provider " + this.provider.getName() + ": " + this);
    }
    this.registered = true;}
```  
  
  
03  
  
漏洞  
点3：  
  
**“com.sony.gemstack.org.dvb.io.ixc.IxcProxy”类包含受保护的方法“invokeMethod”，它可以调用特权上下文下的方法。如果满足以下条件，则可以绕过方法中的权限检查：**  
  
  
- 该方法是公共的和非静态的。  
  
- 该方法的类是 public、non-final 并且可以实例化。  
  
```
class FileImpl extends File implements FileInterface {
  FileImpl(String pathname) {
    super(pathname);
  }
}

```  
  
  
```
interface FileInterface extends Remote {
  public String[] list() throws RemoteException;
}

```  
  
  
**此漏洞可用于泄露文件系统结构以及转储文件（例如，从 '/app0/'）。**  
  
****  
04  
  
漏洞  
点4：  
  
**“compiler receiver thread”从运行时进程接收大小为 0x58 字节的结构：**  
  
```
typedef struct {
  uint8_t cmd; // 0x00
  uint64_t arg0; // 0x08
  uint64_t arg1; // 0x10
  uint64_t arg2; // 0x18
  uint64_t arg3; // 0x20
  uint64_t arg4; // 0x28
  uintptr_t runtime_data; // 0x30
  uintptr_t compiler_data; // 0x38
  uint64_t data1; // 0x40
  uint64_t data2; // 0x48
  uint64_t unk; // 0x50
} CompilerAgentRequest; // 0x58

CompilerAgentRequest req;
while (CompilerAgent::readn(s, &req, sizeof(req)) > 0) {
  uint8_t ack = 0xAA;
  CompilerAgent::writen(s, &ack, sizeof(ack));
  if (req.compiler_data != 0) {
    memcpy(req.compiler_data + 0x28, &req, sizeof(req));        
    ...
  }
  ...
}

```  
  
  
**此结构体在编译器进程的偏移量 0x38（我们称之为 'compiler_data）处包含一个指针，用于备份请求结构。攻击者只需发送一个不受信任的指针，编译器接收器线程就会将数据从请求复制到其内存中。换句话说，我们有一个 write-what-where 原语。攻击者可以通过提供指向 JIT 内存的指针来利用此漏洞，并存储要写入请求的内容。编译器会将这些数据写入 JIT 内存，因此让我们有机会执行任意有效负载。这有严重的影响：- 可以编写 ELF 加载程序来 加载和执行盗版游戏。- 内核利用变得微不足道因为没有 SMEP，人们可以简单地跳转到函数指针损坏的用户。**  
  
**文章翻译自：https://hackerone.com/reports/1379975  By:Trangs**  
  
温馨提示  
  
**免责声明:文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/JzL1qjYyUjmfCKOCRhub9hO0adIAd4HYQFmgFialjNzfCI7oEXicsiciblWqQTwwI4meKKfKeqaN6kXZ5ed696adKA/640?wx_fmt=gif&from=appmsg "")  
   
  
扫描二维码关注我们  
  
   
  
![](https://mmbiz.qpic.cn/mmbiz_gif/JzL1qjYyUjmfCKOCRhub9hO0adIAd4HYQFmgFialjNzfCI7oEXicsiciblWqQTwwI4meKKfKeqaN6kXZ5ed696adKA/640?wx_fmt=gif&from=appmsg "")  
   
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/JzL1qjYyUjmfCKOCRhub9hO0adIAd4HYQp3p6QQXiaz3E42GIdpSkVhDia573iaM78Gr2Uerl8l9v8cSWBS4dpFmA/640?wx_fmt=jpeg&from=appmsg "undefined")  
  
  
