# CPP TLS RemoteShell

## 系統環境
- OS: Ubuntu 20.04
    - Linux 5.4.0-26-generic #30-Ubuntu SMP Mon Apr 20 16:58:30 UTC 2020 x86_64 
- Compiler: gcc version 9.3.0 (Ubuntu 9.3.0-10ubuntu2) 
- OpenSSL: OpenSSL 1.1.1f  31 Mar 2020
- libssl-dev: 1.1.1f-1ubuntu2
- Text Editor: Vscode


## 功能說明
基於 TLS 的 Remote shell

1. Server與Client程式碼皆放置於bin資料夾內
2. 使用./Server ./Client，即可執行SSL shell
3. 使用exit指令， 關閉shell

![](https://i.imgur.com/M7fpPnK.png)



## 系統架構
透過C++與openssl建置，符合TLS規範的SSL Remote shell

以下使用Wireshark抓包進行說明
### 1. TCP三向交握
#### SYN
![](https://i.imgur.com/IQhxsNe.png)
#### SYN,ACK
![](https://i.imgur.com/2dBhQ2j.png)

#### ACK
![](https://i.imgur.com/j4S4eiL.png)

### 2. TLS互相說Hello
#### Client Hello
![](https://i.imgur.com/ilfDdPj.png)


#### Server Hello + Cipher
![](https://i.imgur.com/eo9igye.png)
#### Client Cipher
![](https://i.imgur.com/0SP12xG.png)



### 3.傳送加密資料
#### Server
![](https://i.imgur.com/jGfb4bU.png)
#### Client
![](https://i.imgur.com/LKEeqY7.png)


## 程式碼解說
詳細程式碼重點皆註解於原始碼內

### 定義簽章位置
```cpp
// client.cpp
#define CLIENT_CERT "client.crt"
#define CLIENT_KEY "client.key"
#define CA_CERT "rootca.crt"

// server.cpp
#define SERVER_CERT "server.crt"
#define SERVER_KEY "server.key"
#define CA_CERT "rootca.crt"
```


### 定義監聽PORT與連接IP
```cpp
// client.cpp
#define IP "127.0.0.1"
#define PORT 8777

// server.cpp
#define PORT 8777
```
- 預設Client連接Server的ip是127.0.0.1，如需變更請自行修改後編譯


### 初始化SSL
```cpp
// server.cpp
    SSL_library_init();
    // 載入SSL圖書館

    SSL_load_error_strings();
    // 載入SSL錯誤的String

    ctx = SSL_CTX_new(SSLv23_method());
    // 創建CTX 結構
    // v23: sslv3可向下支援v2

    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

```

### 載入憑證與驗章
```cpp
// server.cpp
    err = SSL_CTX_use_certificate_file(ctx, SERVER_CERT, SSL_FILETYPE_PEM);

    if (err == -1) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    err = SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY, SSL_FILETYPE_PEM);

    if (err == -1) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    err = SSL_CTX_check_private_key(ctx);
    // 確認載入的證書跟私鑰吻合

    if (err == -1) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    err = SSL_CTX_load_verify_locations(ctx, CA_CERT, NULL);
    // 載入CA的cert

    if (!err) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 1);
    // 設定驗證cert
```

### TCP Socket建立
```cpp

    listen_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    // 打開插頭
    // PF_INET = ipv4
    // SOCK_STREAM = TCP
    // IPPROTO_TCP = protocol

    if (listen_sock == -1) {
        perror("socket");
        exit(1);
    }

    bzero(&server_info, sizeof(server_info));
    server_info.sin_family = AF_INET;
    server_info.sin_addr.s_addr = INADDR_ANY;
    server_info.sin_port = htons(PORT);
    // 把 server_info 清0後放入各種資料
    // INADDR_ANY = 0.0.0.0 = all ip

    err =
        bind(listen_sock, (struct sockaddr *)&server_info, sizeof(server_info));
    // 把我家ㄉ地址綁上插頭

    if (err == -1) {
        perror("bind");
        exit(1);
    }

    err = listen(listen_sock, 5);
    // 設定監聽列隊，最多可以排隊5ㄍ人

    cout << "Server start at "
         << "0.0.0.0:" << PORT << endl;

    if (err == -1) {
        perror("listen");
        exit(1);
    }

    client_len = sizeof(client_info);
    // 設定client的info length

    sock = accept(listen_sock, (struct sockaddr *)&client_info, &client_len);
    // 接收請求，成功創立插頭連線

    if (err == -1) {
        perror("sock");
        exit(1);
    }

    inet_ntop(AF_INET, &(client_info.sin_addr.s_addr), client_ip_str,
              INET_ADDRSTRLEN);
    // 把ip轉char[]方便print

    cout << "Get a connection from " << client_ip_str << ":"
         << client_info.sin_port << endl;
```

### SSL連接
```cpp
//server.cpp
    ssl = SSL_new(ctx);
    // 建立新的SSL結構

    if (ssl == NULL) {
        cout << "SSL new Error!" << endl;
        exit(1);
    }

    SSL_set_fd(ssl, sock);
    // 把插頭 串到ssl上面

    err = SSL_accept(ssl);
    // SSL握手(伺服器)
    // ㄇㄉ防疫期間不要亂握手啦幹= =
    // 拱手不握手，請支持SSL三向交拱(?

    if (err == -1) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
```

### 讀取資料並執行shell
```cpp
// server.cpp
    while (1) {
        string read_str;
        bzero(&read_buf, sizeof(read_buf));

        while (strlen(read_buf) == 0) {  // 讀進來ㄉ要不為空
            err = SSL_read(ssl, read_buf, sizeof(read_buf));
            // 讀入Client傳ㄉ東西

            if (err == -1) {
                ERR_print_errors_fp(stderr);
                exit(1);
            }
        }

        read_str = (string)read_buf;
        // 把char轉string

        cout << "Recv " << read_str << endl;
        if (read_str.compare((string) "exit") == 0) {
            string bye = "888888";
            err = SSL_write(ssl, bye.c_str(), bye.length());
            // 如果Client說exit，就回答888888

            if (err == -1) {
                ERR_print_errors_fp(stderr);
                exit(1);
            }

            cout << "Server stop" << endl;
            break;
            //關掉

        } else {
            // 正常執行指令
            string return_data = exec(read_str);
            // 呼叫自定義的exec程式，回傳結果字串

            err = SSL_write(ssl, return_data.c_str(), return_data.length());
            // 輸出給Client

            if (err == -1) {
                ERR_print_errors_fp(stderr);
                exit(1);
            }
        }
    }
```

### SSL關閉
```cpp
// server.cpp
err = SSL_shutdown(ssl);
    // 把SSL關掉

    if (err == -1) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    err = close(sock);
    // 把插頭關掉

    if (err == -1) {
        perror("close");
        exit(1);
    }


    SSL_free(ssl);
    SSL_CTX_free(ctx);

    return 0;
```


## 產生簽章
### 準備工作
```=bash
cd ~
openssl rand -writerand .rnd

mkdir root
cd root
mkdir server
mkdir client
```

- 產生.rnd在家目錄，並建立root/server/client放置的資料夾



### 建立root CA 
```bash
openssl genrsa -aes256 -out root/ca.key 4096
openssl req -new -x509 -days 365 -sha256 \
        -subj "/C=TW/ST=Taipei/O=FOO/OU=BAR/CN=meow1.meow/emailAddress=meow@meow.meow" \
        -key root/ca.key \
        -out root/ca.crt
```
1. 使用rsa的aes256產生ca的key
2. 使用sha256產生ca的x509憑證



### 產生 Server key/csr
```=bash
openssl genrsa -out server/server.key 4096

openssl req -new -sha256 -key server/server.key \
        -subj "/C=TW/ST=Taipei/O=FOO/OU=BAR/CN=meow2.meow/emailAddress=meow@meow.meow" \
        -out server/server.csr
```
1. 使用rsa 4096產生server的key
2. 使用sha256產生server的csr


### 產生 Client key/csr
```=bash
openssl genrsa -out client/client.key 4096
openssl req -new -sha256 -key client/client.key \
        -subj "/C=TW/ST=Taipei/O=FOO/OU=BAR/CN=meow3.meow/emailAddress=meow@meow.meow" \
        -out client/client.csr
```
1. 使用rsa 4096產生client的key
2. 使用sha256產生client的csr


### 頒發憑證
```=bash
openssl x509 -req -CAcreateserial -days 30 -sha256 \
        -CA root/ca.crt -CAkey root/ca.key \
        -in server/server.csr \
        -out server/server.crt 
```
- 頒發Server的憑證


```=bash
openssl x509 -req -CAcreateserial -days 30 -sha256 \
        -CA root/ca.crt -CAkey root/ca.key \
        -in client/client.csr \
        -out client/client.crt 
```
- 頒發Client的憑證

### 驗證憑證
```=bash
openssl verify -CAfile root/ca.crt client/client.crt
openssl verify -CAfile root/ca.crt client/client.crt
```
- 驗證憑證是否由CA頒發



## 遇到困難與心得
非常感謝老師與助教安排這一次的作業，讓我對於TLS的溝通方式有了更進一步的了解。以往對於SSL發憑證的流程，我都是使用certbot透過一鍵的方式產生憑證，並沒有對於細部的功能有太多的了解。這一次我學會了透過openssl自己當CA發取憑證，終於瞭解了操作的步驟。

程式方面，我遇到最大的障礙主要是openssl的library，內部的function真的非常的多，對於第一次使用的我感覺非常的陌生，查詢了許多的doc才理解了大致的運作流程。就算知道了TLS對於憑證交換的流程，對於如何用程式碼來實現也讓我花了好大一番工夫。再次謝謝老師與助教！！