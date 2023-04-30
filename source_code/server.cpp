#include<sys/socket.h>
#include<iostream>
#include<string.h>
#include<unistd.h>
#include<netinet/in.h>
#include<sys/types.h>
#include<arpa/inet.h>
#include<pthread.h>
#include<signal.h>
#include<fstream>
#include<sstream>
#include<string>
#include <ctime> 
#include <vector>
#include <stdint.h>
#include <string_view>
#include <unordered_set>
#include "./json/single_include/nlohmann/json.hpp"

#define NOP 0
#define ADD_TOKEN 1
#define LOGOUT 2

#define OK_200 "200 OK"
#define MOVE_301 "301 Moved Permanently"
#define ERR_403 "403 Forbidden"

using namespace std;
using json = nlohmann::json;
unordered_set<string> path_names{"/", "/Sign", "/Login", "/Logout", "/index.html"};

int thread_limit = 199;
int welcomesocket;

typedef struct {
    string protocal = "HTTP/1.1 ";
    string status_prefix = "Status: ";
    string status;
    string Content_Type = "Content-Type: text/html; charset=utf-8";
    string cookie_prefix = "Set-Cookie: ";
    string tokenid_prefix = "tokenid=";
    string max_age_prefix = "Max-Age=";
    string tokenid = "";
    string max_age = "3600;";
    string cookie_postfix = "Path=/;";
    string data = "";


} Response;
typedef struct {
    string id;
    string username;
    string datetime;
    string text;
} msg_struct;

struct Acc_info
{
    string id;
    string username;
    string pwd;
    string tokenid = "";
};

json to_msg_json(const msg_struct &p) {
    return json{
        {
            p.id,{
                {"username", p.username},
                {"datetime", p.datetime},
                {"text", p.text}
            }
        }
    };
}

json to_json(const Acc_info& p)
{
    return json{
        {
            p.username, {
                    {"pwd", p.pwd},
                    {"tokenid", p.tokenid}
            }
        }
    };
}

void findAndReplaceAll(std::string & data, std::string toSearch, std::string replaceStr)
{
    // Get the first occurrence
    size_t pos = data.find(toSearch);
    // Repeat till end is reached
    while( pos != std::string::npos)
    {
        // Replace this occurrence of Sub String
        data.replace(pos, toSearch.size(), replaceStr);
        // Get the next occurrence from the current position
        pos =data.find(toSearch, pos + replaceStr.size());
    }
}

string compose_res(Response &head, int op= 0) {
    string res = "";
    res += head.protocal;
    res += "\r\n";
    if(op & (ADD_TOKEN)) {
        res += head.cookie_prefix;
        res += head.tokenid_prefix;
        res += head.tokenid;
        res += "; ";
        res += head.max_age_prefix;
        res += head.max_age;
        res += head.cookie_postfix;
        res += "\r\n";
    }
    if(op & LOGOUT) {
        res += head.cookie_prefix;
        res += head.tokenid_prefix;
        res += "deletedcookie; ";
        res += "expires=Thu, 01-Jan-1970 00:00:01 GMT; Max-Age=-1671817701;";
        res += "\r\n";
    }
    res += head.Content_Type;
    res += "\r\n";
    res += head.status_prefix;
    res += head.status;
    res += "\r\n\n";
    res += head.data;
    return res;
}


string fetchpage(const char *filename) 
{   char buf[9192];
    long lSize, result;
    FILE *pFile;

    pFile = fopen (filename , "r" );
    if (pFile==NULL) {fputs ("File error",stderr); exit (1);}
    
    // obtain file size:
    fseek (pFile , 0 , SEEK_END);
    lSize = ftell (pFile);
    rewind (pFile);

    // copy the file into the buffer:
    result = fread(buf+strlen(buf),1,lSize,pFile);
    if (result != lSize) {fputs ("Reading error",stderr); exit (3);}
    fclose (pFile);

    // Response res;
    // res.status = "200 OK";
    // res.data = string(buf);
    // return compose(res);
    return string(buf);
}


string extract_head_cookie(char buf[]) {
    string text = string(buf), pattern = "Cookie: tokenid=";
    int m = strlen(buf);
    int n = pattern.length();
    int cookie_offset = -1, cookie_end_offset = -1;
 
    if((cookie_offset = text.find(pattern)) == string::npos) {
        // Dont find cookie;
        return "";
    }
    pattern = ";";
    if((cookie_end_offset = text.find(pattern, cookie_offset+16)) == string::npos) {
        pattern = "\n";
        return text.substr(cookie_offset+16, text.find(pattern, cookie_offset+16)-cookie_offset-16);
    }
    text = text.substr(cookie_offset, cookie_end_offset-cookie_offset);
    cookie_end_offset = text.find_last_of(";");
    return text.substr(0, cookie_end_offset);

}

char* extract_set_username(char username[], char buf[]) 
{
    char *end_pos = (char *)std::char_traits<char>::find(buf, 70, '&');
    if(end_pos == nullptr) {
        return nullptr;
    }

    strncpy(username, buf, end_pos-buf);
    cout << "extracted username: " << username << endl;
    return end_pos;
}

char* extract_set_pattern(char ans[], char* buf, char pattern) {

    char *end_pos = (char *)std::char_traits<char>::find(buf, 70, pattern);
    if(end_pos == nullptr) {
        return end_pos;
    }

    strncpy(ans, buf, end_pos-buf);
    return end_pos;
}

string Signin(char buf[], int offset) {
    cout << "Accept Signin Request" << endl;
    char username[10] = {0}, pwd[10] = {0};
    Response res;
    Acc_info info;
    
    char* pinfo_end;
    if((pinfo_end = extract_set_username(username, buf+offset+5)) == nullptr){
        res.status = ERR_403;
        res.data = (json{{"result", "FALSE"}}).dump();
        return compose_res(res);
    }

    if((pinfo_end = extract_set_pattern(pwd, pinfo_end+5, ' ')) == nullptr){
        res.status = ERR_403;
        res.data = (json{{"result", "FALSE"}}).dump();
        return compose_res(res);
    }
    
    std::ifstream ifs("account.json");
    json jf = json::parse(ifs);
    ifs.close();
    info.id = jf.size();
    info.username = string(username);
    info.pwd = string(pwd);
    info.tokenid = string(info.username);
    info.tokenid += "_tokenid";

    if(jf.contains(info.username)) {
        res.status = ERR_403;
        res.data = (json{{"result", "FALSE"}}).dump();
        return compose_res(res);
    }

    jf.update(to_json(info));

    ofstream ofs("account.json");
    ofs << jf << endl;
    ofs.close(); 
    res.data = (json{{"result", "TRUE"}}).dump();
    res.status = OK_200;
    return compose_res(res);
}


string process_request(char buf[], char command[]) {
    const char *reqtype;
    char query[80];
    unsigned int command_start, current_buf_offset = 0;
    cout << buf << endl;
    if(strncmp("GET", buf, 3) == 0) {
        reqtype = "GET";
        current_buf_offset=3;
    }
    // else if (strncmp("POST", buf, 4) == 0) {
    //     reqtype = "POST";
    //     current_buf_offset = 4;
    // }
    else {
        goto returnhomepage;
    }
    current_buf_offset ++;
    command_start = current_buf_offset;

    while(strncmp(buf+current_buf_offset, "?", 1) != 0 && strncmp(buf+current_buf_offset, " ", 1) != 0) {
        current_buf_offset++;
    }

    memcpy(command, buf+command_start, current_buf_offset-command_start);
    cout << "command = " << string(command) << endl; 
    if(strcmp("/", command) == 0) {
        goto returnhomepage;
    }
    else if (strcmp("/Sign", command) == 0) {
        return Signin(buf, current_buf_offset);

    }else if(strcmp("/Login", command) == 0) {
        cout << "Accept Login Request" << endl;
        Response res;
        
        char username[10] = {0}, pwd[10] = {0};
        char *ptmp;
        if((ptmp = extract_set_username(username, buf+current_buf_offset+5)) == nullptr || (ptmp = extract_set_pattern(pwd, ptmp+5, ' ')) == nullptr) {
            res.status = ERR_403;
            res.data = json{{"result", ERR_403},{"reason", "USERNAME DOESN'T EXIST."}}.dump();
            return compose_res(res);
        }
        std::ifstream ifs("account.json");
        json jf = json::parse(ifs);
        ifs.close();

        if(!jf.contains(string(username))) {
            // username dont exist
            res.status = ERR_403;
            res.data = json{{"result", ERR_403},{"reason", "USERNAME DOESN'T EXIST."}}.dump();
            return compose_res(res);
        }

        string tmp = jf.at(username).at("pwd");

        if(strcmp(tmp.c_str(), pwd) != 0) {
            // pwd wrong
            res.status = ERR_403;
            res.data = json{{"result", ERR_403},{"reason", "WRONG PASSWORD"}}.dump();
            return compose_res(res);
        }
        res.status = OK_200;
        res.tokenid = jf.at(username).at("tokenid");
        string redirect_addr = "http://140.112.29.206:8081/index.html?acc=";
        redirect_addr += string(username);
        res.data = (json{{"Location", redirect_addr}}).dump();
        
        return compose_res(res, ADD_TOKEN);

    }else if(strcmp("/index.html", command) == 0){
        // check cookie
        cout << "Accept index request" << endl;
        Response res;
        string extracted_tokenid = extract_head_cookie(buf);
        if((strcmp(extracted_tokenid.c_str(), "") == 0) || (strcmp(extracted_tokenid.c_str(), "deletedcookie") == 0)) {
            // have no cookie
            res.status = MOVE_301;
            res.data = fetchpage("response.html");
        }else {
            res.status = OK_200;
            res.data = fetchpage("index.html");
        }

        return compose_res(res);
    }else if(strcmp("/Logout", command) == 0) {
        // TODO : clear cookie & return home page
        cout << "Accept Logout request" << endl;
        Response res;
        res.status = MOVE_301;
        res.max_age = "0";
        res.tokenid = extract_head_cookie(buf);
        res.data = (json{{"Location", "http://140.112.29.206:8081/"}}).dump();
        return compose_res(res, 0|LOGOUT);
    }else if(strcmp("/getusername", command) == 0) {
        Response res;
        string extracted_tokenid = extract_head_cookie(buf);
        int username_end = extracted_tokenid.find("_");
        res.status = OK_200;
        res.tokenid = extracted_tokenid;
        res.data = json{{"result", extracted_tokenid.substr(0,username_end)}}.dump();
        return compose_res(res, 0|ADD_TOKEN);
    }else if(strcmp("/index.html/leave_msg", command) == 0) {
        Response res;
        string extracted_tokenid = extract_head_cookie(buf);
        extracted_tokenid = string(extracted_tokenid.begin(), extracted_tokenid.end()-9);
        // if((strcmp(extracted_tokenid.c_str(), "") == 0) || (strcmp(extracted_tokenid.c_str(), "deletedcookie") == 0)) {
        //     // have no cookie
        //     res.status = MOVE_301;
        //     res.data = fetchpage("response.html");
        //     return compose_res(res);
        // }

        char username[10], message[500], datetime[100];
        memset(username, '\0', sizeof(username));
        memset(message, '\0', sizeof(message));
        memset(datetime, '\0', sizeof(datetime));
        msg_struct msg;
        
        char* ptmp = extract_set_pattern(message, buf+current_buf_offset+6, ' ');
        string mesg = string(message);
        findAndReplaceAll(mesg, "%20", " ");
        time_t now = time(0);
        // convert now to string form
        char* dt = ctime(&now);
        strcpy(datetime, dt);
        std::ifstream ifs("message_board.json");
        json jf = json::parse(ifs);
        ifs.close();
        msg.id = to_string(jf.size());
        msg.username = extracted_tokenid;
        msg.datetime = string(datetime);
        msg.text = mesg;

        // cout << jf.dump() << endl;
        jf.update(to_msg_json(msg));
        // cout << jf.dump() << endl;
        ofstream ofs("message_board.json");
        ofs << jf << endl;
        ofs.close();
        res.data = (json{{"result", "SUCCESS"}}).dump();
        res.status = OK_200;
        return compose_res(res);
    }else if(strcmp("/index.html/req_msg_board", command) == 0 ) {
        Response res;
        std::ifstream ifs("message_board.json");
        json jf = json::parse(ifs);
        ifs.close();
        
        res.data = (json{{"result", jf.dump()}}).dump();
        res.status = OK_200;
        return compose_res(res);
    }


    returnhomepage:
        Response res;
        string extracted_tokenid = extract_head_cookie(buf);
        if((strcmp(extracted_tokenid.c_str(), "") == 0)) {
            // have no cookie
            res.status = MOVE_301;
            res.data = fetchpage("response.html");
        }else {
            res.status = OK_200;
            res.data = fetchpage("index.html");
        }
        return compose_res(res);
    
}


void *socketThread(void *arg) 
{
    int childsocket = *(int *)arg;
    char buffer[2048];
    int nBytes = 1, i;
    struct sockaddr_in childaddr;
    int len = sizeof(childaddr);
    time_t now = time(0);
    char* dt = ctime(&now);
    char command[40];
    
    memset(command, '\0', sizeof(command));
    memset(buffer, '\0', sizeof(buffer));
    memset(&childaddr, '\0', sizeof(childaddr));
    cout << "連線日期和時間：" << dt << endl;
    
    while(1) {
        if((nBytes = recv(childsocket, buffer, 2048, 0)) > 0) {
            if(strcmp("exit()", buffer) == 0) { // exit
                break;
            }
            memset(command, '\0', 40);

            if(strncmp("GET", buffer, 3) == 0) {
                cout << "Accept Request" << endl;
                const char *buf;
                string res = process_request(buffer, command);
                buf = res.c_str();
                
                // if(strlen(buf) == 2) {
                //     cout << "is  at -1 here" << endl;
                //     break;
                // }
                send(childsocket, buf, strlen(buf), 0);
                memset(buffer, '\0', sizeof(buffer));
                memset(command, '\0', sizeof(command));
                break;
            }
            else {
                cout << buffer << endl;
                memset(buffer, '\0', sizeof(buffer));
            }
        }
        
    }
    close(childsocket);
    pthread_exit(NULL);
}

void signal_callback_handler(int signum);

int main() 
{
    signal(SIGINT, signal_callback_handler);
    int welcomesocket, newsocket, port_num = 8081, clientLen, nBytes, i;
    char buffer[1024];
    struct sockaddr_in serveraddr;
    struct sockaddr_storage serverstorage;
    socklen_t addr_size;
    pthread_t tid[200];

    welcomesocket = socket(AF_INET, SOCK_STREAM, 0);
    memset(&serveraddr, '\0', sizeof(serveraddr));
    cout << "Socket Created..." << endl;
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(port_num);
    serveraddr.sin_addr.s_addr = inet_addr("xxx.xxx.xxx.xxx");
    memset(serveraddr.sin_zero, '\0', sizeof(serveraddr.sin_zero));

    // Bind Part
    if(bind(welcomesocket, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) != 0) {
        close(welcomesocket);
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }
    cout << "Bind Complete..." << endl;
    
    // Listen Part
    if(listen(welcomesocket, 50) == 0) {
        cout << "Listening..." << endl;
    }else {
        close(welcomesocket);
        perror("Listed failed");
        exit(EXIT_FAILURE);
    }
    i = 0;
    addr_size = sizeof(serverstorage);
    while(1){
        i=0;
        while(i < thread_limit){
            newsocket = accept(welcomesocket, (struct sockaddr *)&serverstorage, &addr_size);
            cout << "thread used: " << i << endl;
            if(pthread_create(&tid[i++], NULL, socketThread, &newsocket) < 0) {    
                perror("Thread Create Failed\n");
                exit(EXIT_FAILURE);
            }
        }

        i = 0;
        while(i < thread_limit) {
            pthread_join(tid[i++],NULL);
            printf("Thread %d joined.\n", i);
        }
    }
    close(welcomesocket);
    return 0;
}


void signal_callback_handler(int signum) {
    close(welcomesocket);
    exit(EXIT_FAILURE);
}