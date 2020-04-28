#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
using namespace std;

#define SERVER_CERT "server.crt"
#define SERVER_KEY "server.key"
#define CA_CERT "rootca.crt"

#define PORT 8777
#define MAXBUF 4096

string exec(string);

int main() {
    /* 宣告需要ㄉ變數 */
    int err;          //紀錄Errorㄉ回傳值
    int listen_sock;  // socket的回傳值
    int sock;         // accept的回傳值

    struct sockaddr_in server_info;
    struct sockaddr_in client_info;
    unsigned int client_len;

    char *str;
    char read_buf[MAXBUF];
    char client_ip_str[INET_ADDRSTRLEN];

    SSL_CTX *ctx;
    SSL *ssl;
    X509 *client_cert = NULL;

    //-------------------------------------
    /* 初始化SSL */

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

    //-------------------------------------
    /* 載入本地端證書 */

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

    //-------------------------------------

    /* 設定TCP插頭 */

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

    //-------------------------------------

    /* 設定SSL 連接 */

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

    //-------------------------------------

    /* 顯示SSL資訊 */
    cout << "Start SSL connection with " << SSL_get_cipher(ssl) << endl;

    client_cert = SSL_get_peer_certificate(ssl);
    // 讀Client的cert

    if (client_cert != NULL) {
        cout << "Client Cert:" << endl;

        str = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0);
        // 讀入Clientㄉsubject_name

        cout << "subject: " << str << endl;
        free(str);
        // 免費字串

        str = X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0);
        // 讀入issuer_name

        cout << "issuer: " << str << endl;
        free(str);
        // 免費字串

    } else {
        cout << "Client no cert ?__?" << endl;
    }

    //-------------------------------------
    /* 資料傳輸 */
    // 無窮迴圈直到client輸入exit

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

    //-------------------------------------
    /* SSL關閉 */

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
    // 因為要關ㄌ
    // 所以把SSL跟CTX都設定為免費

    return 0;
    // 主程式結束ㄌ！
}

string exec(string cmd) {
    /* 自定義exec程式，執行cmd回傳結果String */
    string file_name = "tmp";
    system((cmd + " > " + file_name).c_str());
    // 用pipeline的方法把cmd的東西丟到tmp檔案

    ifstream file(file_name);
    return {istreambuf_iterator<char>(file), istreambuf_iterator<char>()};
    // 輸出tmp檔案
}
