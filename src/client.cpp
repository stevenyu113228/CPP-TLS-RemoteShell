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
#include <iostream>
using namespace std;

#define CLIENT_CERT "client.crt"
#define CLIENT_KEY "client.key"
#define CA_CERT "rootca.crt"

#define IP "127.0.0.1"
#define PORT 8777
#define MAXBUF 4096

int main() {
    /* 宣告需要ㄉ變數 */
    int err;   //紀錄Errorㄉ回傳值
    int sock;  // socket的回傳值

    struct sockaddr_in server_info;
    char *str;

    char read_buf[MAXBUF];
    char write_buf[MAXBUF];

    SSL_CTX *ctx;
    SSL *ssl;
    X509 *server_cert = NULL;

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
        cout << "CTX new Error!" << endl;
        exit(1);
    }

    //-------------------------------------
    /* 載入本地端證書 */

    err = SSL_CTX_use_certificate_file(ctx, CLIENT_CERT, SSL_FILETYPE_PEM);

    if (err == -1) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    err = SSL_CTX_use_PrivateKey_file(ctx, CLIENT_KEY, SSL_FILETYPE_PEM);

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
    //載入CA的cert

    if (!err) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 1);
    //設定驗證cert

    //-------------------------------------

    /* 設定TCP插頭 */

    sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    // 打開插頭
    // PF_INET = ipv4
    // SOCK_STREAM = TCP
    // IPPROTO_TCP = protocol

    if (sock == -1) {
        perror("socket");
        exit(1);
    }

    bzero(&server_info, sizeof(server_info));
    server_info.sin_family = AF_INET;
    server_info.sin_port = htons(PORT);
    server_info.sin_addr.s_addr = inet_addr(IP);
    // 把 server_info 清0後放入各種資料

    err = connect(sock, (struct sockaddr *)&server_info, sizeof(server_info));
    // 連接上Server

    cout << "Connect to " << IP << ":" << PORT << endl;

    if (err == -1) {
        perror("connect");
        exit(1);
    }

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

    err = SSL_connect(ssl);
    // SSL握手(客戶端)
    // ㄇㄉ防疫期間不要亂握手啦幹= =
    // 拱手不握手，請支持SSL三向交拱(?

    if (err == -1) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    //-------------------------------------

    /* 顯示SSL資訊 */

    cout << "Start SSL connection with " << SSL_get_cipher(ssl) << endl;

    server_cert = SSL_get_peer_certificate(ssl);
    // 讀Server的Cert

    if (server_cert != NULL) {
        cout << "Client Cert:" << endl;

        str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
        // 讀入Serverㄉsubject_name

        cout << "subject: " << str << endl;
        free(str);
        // 免費字串

        str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
        // 讀入issuer_name

        cout << "issuer: " << str << endl;
        free(str);
        // 免費字串

    } else {
        cout << "Server no cert ?__?" << endl;
    }
    cout << endl;
    //-------------------------------------
    /* 資料傳輸 */
    // 無窮迴圈直到client輸入exit

    while (1) {
        bzero(&read_buf, sizeof(read_buf));

        cout << "> ";
        string write_str;
        getline(cin, write_str);
        // 讀入要輸出的command

        err = SSL_write(ssl, write_str.c_str(), write_str.length());
        // 透過SSL丟給伺服器

        if (err == -1) {
            ERR_print_errors_fp(stderr);
            exit(1);
        }

        while (strlen(read_buf) == 0) {  // 讀進來ㄉ要不為空
            err = SSL_read(ssl, read_buf, sizeof(read_buf));
            // 讀入Server吐回來ㄉ東西

            if (err == -1) {
                ERR_print_errors_fp(stderr);
                exit(1);
            }
        }

        cout << read_buf << endl;
        // 輸出Server吐ㄉ東西

        if (write_str.compare((string) "exit") == 0) {  // 如果輸入exit就8888
            break;
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