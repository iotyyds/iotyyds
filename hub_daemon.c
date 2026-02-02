#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>
#include <sys/time.h>
#include "cJSON.h"
#define PORT 9999
static char current_token[64] = "";

void send_json_response(int sock, int status, const char *msg) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "status", status);
    cJSON_AddStringToObject(root, "msg", msg);
    char *json_str = cJSON_PrintUnformatted(root);
    uint32_t len = htonl(strlen(json_str));
    send(sock, &len, 4, 0);
    send(sock, json_str, strlen(json_str), 0);
    free(json_str);
    cJSON_Delete(root);
}
void send_cmd_output(int sock, const char *output) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "status", 200);
    cJSON_AddStringToObject(root, "output", output);
    char *json_str = cJSON_PrintUnformatted(root);
    uint32_t len = htonl(strlen(json_str));
    send(sock, &len, 4, 0);
    send(sock, json_str, strlen(json_str), 0);
    free(json_str);
    cJSON_Delete(root);
}
int is_valid_ip(const char *ip) {
    if (!ip) return 0;
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip, &(sa.sin_addr));
}
int is_safe_interface(const char *iface) {
    if (!iface) return 0;
    if (strchr(iface, ' ')) return 0;
    return 1;
}
void handle_auth(int sock, cJSON *params) {
    cJSON *user = cJSON_GetObjectItem(params, "user");
    cJSON *pass = cJSON_GetObjectItem(params, "pass");

    if (cJSON_IsString(user) && cJSON_IsString(pass)) {
        if (strcmp(user->valuestring, "admin") == 0 && strcmp(pass->valuestring, "root") == 0) {
            srand(time(NULL) ^ getpid());
            snprintf(current_token, sizeof(current_token), "%08x%08x", rand(), rand());

            cJSON *resp = cJSON_CreateObject();
            cJSON_AddNumberToObject(resp, "status", 200);
            cJSON *data = cJSON_CreateObject();
            cJSON_AddStringToObject(data, "token", current_token);
            cJSON_AddItemToObject(resp, "data", data);

            char *str = cJSON_PrintUnformatted(resp);
            uint32_t len = htonl(strlen(str));
            send(sock, &len, 4, 0);
            send(sock, str, strlen(str), 0);
            free(str);
            cJSON_Delete(resp);
            return;
        }
    }
    send_json_response(sock, 403, "Authentication Failed");
}
void handle_get_time(int sock) {
    char buf[32];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm_info);

    cJSON *res = cJSON_CreateObject();
    cJSON_AddNumberToObject(res, "status", 200);
    cJSON_AddStringToObject(res, "current_time", buf);

    char *str = cJSON_PrintUnformatted(res);
    uint32_t len = htonl(strlen(str));
    send(sock, &len, 4, 0);
    send(sock, str, strlen(str), 0);
    free(str);
    cJSON_Delete(res);
}
void handle_set_time(int sock, cJSON *params) {
    cJSON *time_str = cJSON_GetObjectItem(params, "time");
    if (!cJSON_IsString(time_str)) {
        send_json_response(sock, 400, "Invalid time parameter");
        return;
    }
    const char *t = time_str->valuestring;
    struct tm tm_info;
    memset(&tm_info, 0, sizeof(tm_info));

    if (strptime(t, "%Y-%m-%d %H:%M:%S", &tm_info) == NULL) {
        send_json_response(sock, 400, "Invalid time format (expected YYYY-MM-DD HH:MM:SS)");
        return;
    }

    time_t new_time = mktime(&tm_info);
    struct timeval tv = { .tv_sec = new_time, .tv_usec = 0 };

    if (settimeofday(&tv, NULL) == 0) {
        send_json_response(sock, 200, "System time updated successfully");
    } else {
        perror("settimeofday");
        send_json_response(sock, 500, "Failed to set system time (permission denied?)");
    }
}

// 3️⃣ tools 模块：ping（存在命令注入漏洞）
void handle_ping(int sock, cJSON *params) {
    cJSON *target = cJSON_GetObjectItem(params, "ip");
    cJSON *iface = cJSON_GetObjectItem(params, "dev");
    cJSON *count = cJSON_GetObjectItem(params, "cnt");
    if (!cJSON_IsString(target) || !cJSON_IsString(iface)) {
        send_json_response(sock, 400, "Invalid Parameters");
        return;
    }
    if (!is_valid_ip(target->valuestring)) {
        send_json_response(sock, 400, "Invalid IP Address");
        return;
    }
    if (!is_safe_interface(iface->valuestring)) {
        send_json_response(sock, 400, "Invalid Interface Name (Space detected)");
        return;
    }

    int ping_count = 3;
    if (cJSON_IsNumber(count)) {
        ping_count = count->valueint;
        if (ping_count < 1 || ping_count > 5) ping_count = 3;
    }

    char command[512];
    snprintf(command, sizeof(command), "ping -I %s -c %d %s 2>&1",
             iface->valuestring, ping_count, target->valuestring);
    printf("[System] Executing: %s\n", command);

    FILE *fp = popen(command, "r");
    if (fp) {
        char buffer[2048] = {0};
        fread(buffer, 1, 2047, fp);
        pclose(fp);
        send_cmd_output(sock, buffer);
    } else {
        send_json_response(sock, 500, "Internal Error");
    }
}

// ---------------- 请求处理 ----------------

void process_request(int sock, char *json_body) {
    cJSON *root = cJSON_Parse(json_body);
    if (!root) {
        send_json_response(sock, 400, "JSON Parse Error");
        return;
    }

    cJSON *module = cJSON_GetObjectItem(root, "module");
    cJSON *method = cJSON_GetObjectItem(root, "method");
    cJSON *params = cJSON_GetObjectItem(root, "params");
    cJSON *token = cJSON_GetObjectItem(root, "token");

    if (!cJSON_IsString(module) || !cJSON_IsString(method)) {
        send_json_response(sock, 400, "Missing module or method");
        cJSON_Delete(root);
        return;
    }

    // 登录接口不需要 token
    if (strcmp(module->valuestring, "auth") == 0 && strcmp(method->valuestring, "login") == 0) {
        handle_auth(sock, params);
        cJSON_Delete(root);
        return;
    }

    // 其他接口都需要 token 验证
    if (!token || strcmp(token->valuestring, current_token) != 0) {
        send_json_response(sock, 401, "Unauthorized");
        cJSON_Delete(root);
        return;
    }

    if (strcmp(module->valuestring, "system") == 0) {
        if (strcmp(method->valuestring, "get_time") == 0)
            handle_get_time(sock);
        else if (strcmp(method->valuestring, "set_time") == 0)
            handle_set_time(sock, params);
        else
            send_json_response(sock, 404, "Method not found");
    }
    else if (strcmp(module->valuestring, "tools") == 0) {
        if (strcmp(method->valuestring, "ping") == 0)
            handle_ping(sock, params);
        else
            send_json_response(sock, 404, "Method not found");
    }
    else {
        send_json_response(sock, 404, "Module not found");
    }

    cJSON_Delete(root);
}

// ---------------- 客户端处理 ----------------

void client_handler(int sock) {
    struct timeval tv = {10, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    while (1) {
        uint32_t net_len;
        if (recv(sock, &net_len, 4, 0) != 4) break;
        uint32_t len = ntohl(net_len);
        if (len > 8192) {
            send_json_response(sock, 400, "Payload Too Large");
            break;
        }

        char *buffer = malloc(len + 1);
        memset(buffer, 0, len + 1);
        if (recv(sock, buffer, len, 0) != len) {
            free(buffer);
            break;
        }

        process_request(sock, buffer);
        free(buffer);
    }
    close(sock);
}

// ---------------- 主函数 ----------------

int main() {
    int server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);

    // 防止僵尸进程
    signal(SIGCHLD, SIG_IGN);

    // 创建 socket
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        return 1;
    }

    listen(server_sock, 10);
    printf("IoT Hub Daemon listening on port %d...\n", PORT);
    int menu_printed = 0;   

    while (1) {
        client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &addr_len);
        if (client_sock < 0)
            continue;

        int need_print_menu = 0;
        if (!menu_printed) {
            menu_printed = 1;
            need_print_menu = 1;
        }

        if (fork() == 0) {
            // 子进程
            close(server_sock);

            if (need_print_menu) {
                const char *menu =
                    "通信协议说明:\n"
                    "  - 所有请求均为 JSON 格式\n"
                    "  - 前4字节为长度 (大端序)\n"
                    "可用功能:\n"
                    "   auth.login\n"
                    "   system.get_time\n"
                    "   system.set_time\n"
                    "   tools.ping\n";
                write(client_sock, menu, strlen(menu));
            }

            client_handler(client_sock);
            exit(0);
        }
        close(client_sock);
    }

    return 0;
}