#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <iostream>
#include <stdexcept>
#include <arpa/inet.h>
#include <thread>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <mutex>
#include <vector>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>

#include "readFile.h"

using namespace std;

void error(const char *msg)
{
    perror(msg);
    exit(1);
}

enum Tracker_role {PRIMARY, SECONDARY};
vector<string> commandLog;
Tracker_role role;
mutex state_mutex;
int hbSockFd = -1;
mutex hbSendMutex;
bool peerAlive = true;

// STATE MANAGEMENT
struct User
{
    string userId;
    string Password;
    bool isLoggedin = false;
};

struct Group
{
    string groupId;
    string ownerId;
    unordered_set<string> members;               
    vector<string> joinRequests; 
};

struct FileInfo {
    string fileName;
    long long fileSize;
    string ownerId;
    string combinedHashes;
    unordered_map<string, vector<bool>> seeders;
};

struct ClientInfo {
    string ipAddr;
    int port;
};

unordered_map<string, User> users;
unordered_map<string, Group> groups;
unordered_map<int, string> sessionMap;
unordered_map<string, unordered_map<string, FileInfo>> files;
unordered_map<string, ClientInfo> clientAddresses;

void appendCommandLog(const string cmd){
    lock_guard<mutex> lock(state_mutex);
    commandLog.push_back(cmd);
}

void monitorPeer() {
    while(true){
        this_thread::sleep_for(chrono::seconds(1));
        if(role == Tracker_role::SECONDARY && peerAlive == false){
            cout << "[Monitor] Secondary taking primary position" << endl;
            role = Tracker_role::PRIMARY;
            peerAlive = true;
        }
    }
}

// CLIENT COMMAND EXECUTORS
string getLoggedInUser(int clientSock) {
    if (sessionMap.find(clientSock) != sessionMap.end()) {
        return sessionMap[clientSock];
    }
    return "";
}

void sendResponse(int clientSock, const string& message) {
    if(role == Tracker_role::PRIMARY){
        string msg = message + "\n";
        send(clientSock, msg.c_str(), msg.size(), 0);
    }
}

void handleCreateUser(const string& userId, const string& password, int clientSock) {
    if (users.find(userId) != users.end()) {
        sendResponse(clientSock, "User already exists");
        return;
    }

    users[userId] = User{userId, password, false};
    sendResponse(clientSock, "User created successfully");
}

void handleLogin(string userId, const string password, int clientSock) {
    if(!getLoggedInUser(clientSock).empty()){
        sendResponse(clientSock, "Logout current User before login.");
        return;
    }
    
    auto it = users.find(userId);
    if (it == users.end()) {
        sendResponse(clientSock, "User not found");
        return;
    }
    if (it->second.Password != password) {
        sendResponse(clientSock, "Invalid password");
        return;
    }
    it->second.isLoggedin = true;
    sessionMap[clientSock] = userId;
    sendResponse(clientSock, "Login successful");
}

void handleCreateGroup(const string& groupId, int clientSock) {
    string userId = getLoggedInUser(clientSock);
    if (userId.empty()) {
        sendResponse(clientSock, "You must login first");
        return;
    }

    if (groups.find(groupId) != groups.end()) {
        sendResponse(clientSock, "Group already exists");
        return;
    }

    groups[groupId] = Group{groupId, userId, {userId}, {}};
    sendResponse(clientSock, "Group created successfully");
}

void handleJoinGroup(const string& groupId, int clientSock) {
    string userId = getLoggedInUser(clientSock);
    if (userId.empty()) {
        sendResponse(clientSock, "You must login first");
        return;
    }

    auto it = groups.find(groupId);
    if (it == groups.end()) {
        sendResponse(clientSock, "Group does not exist");
        return;
    }

    if (find(it->second.joinRequests.begin(), it->second.joinRequests.end(), userId) != it->second.joinRequests.end()) {
        sendResponse(clientSock, "Join request already sent");
        return;
    }

    it->second.joinRequests.push_back(userId);
    sendResponse(clientSock, "Join request sent to group owner");
}

void handleLeaveGroup(const string& groupId, int clientSock){
    string userId = getLoggedInUser(clientSock);
    if(userId.empty()){
        sendResponse(clientSock, "You must login first");
        return;
    }
    if(groups.count(groupId) == 0){
        sendResponse(clientSock, "Group Id doesn't exist");
        return;
    }
    Group &g = groups[groupId];
    if(g.ownerId == userId){
        sendResponse(clientSock, "you are the Owner of group. you cannot exit");
        return;
    }
    if(g.members.count(userId) == 0){
        sendResponse(clientSock, "You are not a member of that group");
        return;
    }
    
    g.members.erase(userId);
    sendResponse(clientSock, "Left the group with id: " + groupId);
}

void handleListGroups(int clientSock) {
    if (groups.empty()) {
        sendResponse(clientSock, "No groups available");
        return;
    }
    string response = "Available groups:\n";
    for (auto [groupName, groupData] : groups) {
        response += groupName + " (Owner: " + groupData.ownerId + ")\n";
    }

    sendResponse(clientSock, response);
}

void handleListRequests(const string& groupId, int clientSock) {
    string userId = getLoggedInUser(clientSock);
    if (userId.empty()) {
        sendResponse(clientSock, "Kindly login before performing any action");
        return;
    }
    if (groups.count(groupId) == 0) {
        sendResponse(clientSock, "Group Id doesn't exist");
        return;
    }
    Group &g = groups[groupId];
    if (g.ownerId != userId) {
        sendResponse(clientSock, "Only group owner can see join requests");
        return;
    }
    if (g.joinRequests.empty()) {
        sendResponse(clientSock, "No pending requests for group: " + groupId);
        return;
    }
    string response = "Pending join requests for " + groupId + ":\n";

    for (auto &userRequested : g.joinRequests) {
        response += "- " + userRequested + "\n";
    }
    sendResponse(clientSock, response);
}

void handleAcceptRequest(const string groupId, const string& reqUserId, int clientSock) {
    string userId = getLoggedInUser(clientSock);
    if (userId.empty()) {
        sendResponse(clientSock, "You must login first");
        return;
    }

    if (groups.count(groupId) == 0) {
        sendResponse(clientSock, "Group Id doesn't exist");
        return;
    }

    Group &g = groups[groupId];

    if (g.ownerId != userId) {
        sendResponse(clientSock, "Only owner can accept the invite request!");
        return;
    }
    
    auto it = find(g.joinRequests.begin(), g.joinRequests.end(), reqUserId);
    if (it != g.joinRequests.end()) {
        g.joinRequests.erase(it);
        g.members.insert(reqUserId);
        sendResponse(clientSock, "Accepted join request. " + reqUserId + " is now a member of group " + groupId);
    } else {
        sendResponse(clientSock, "No join request from user " + reqUserId);
    }
    return;
}

void handleLogout(int clientSock){
    string userId = sessionMap[clientSock];
    if (!userId.empty()) {
        users[userId].isLoggedin = false;
        sessionMap.erase(clientSock);
    }
    sendResponse(clientSock, "user LoggedOut");
}

// FILE MANAGEMENT FUNCTIONS
void handleUploadFile(const string& groupId, const string& fileName, const string& fileSize, 
                      const string& hashes, int clientSock) {
    string userId = getLoggedInUser(clientSock);
    if (userId.empty()) {
        sendResponse(clientSock, "You must login first");
        return;
    }

    if (groups.count(groupId) == 0) {
        sendResponse(clientSock, "Group does not exist");
        return;
    }

    Group &g = groups[groupId];
    if (g.members.count(userId) == 0) {
        sendResponse(clientSock, "You are not a member of this group");
        return;
    }

    long long fileSz = stoll(fileSize);
    int numPieces = (fileSz + 524287) / 524288;
    vector<bool> allPieces(numPieces, true);

    FileInfo fInfo;
    fInfo.fileName = fileName;
    fInfo.fileSize = fileSz;
    fInfo.ownerId = userId;
    fInfo.combinedHashes = hashes;
    fInfo.seeders[userId] = allPieces;

    files[groupId][fileName] = fInfo;
    
    sendResponse(clientSock, "File uploaded successfully");
}

void handleListFiles(const string& groupId, int clientSock) {
    string userId = getLoggedInUser(clientSock);
    if (userId.empty()) {
        sendResponse(clientSock, "You must login first");
        return;
    }

    if (groups.count(groupId) == 0) {
        sendResponse(clientSock, "Group does not exist");
        return;
    }

    Group &g = groups[groupId];
    if (g.members.count(userId) == 0) {
        sendResponse(clientSock, "You are not a member of this group");
        return;
    }

    if (files.count(groupId) == 0 || files[groupId].empty()) {
        sendResponse(clientSock, "No files in this group");
        return;
    }

    string response = "Files in group " + groupId + ":\n";
    for (auto &[fName, fInfo] : files[groupId]) {
        response += fName + " (" + to_string(fInfo.fileSize) + " bytes)\n";
    }

    sendResponse(clientSock, response);
}

void handleGetFileInfo(const string& groupId, const string& fileName, int clientSock) {
    string userId = getLoggedInUser(clientSock);
    if (userId.empty()) {
        sendResponse(clientSock, "ERROR:You must login first");
        return;
    }

    if (groups.count(groupId) == 0) {
        sendResponse(clientSock, "ERROR:Group does not exist");
        return;
    }

    Group &g = groups[groupId];
    if (g.members.count(userId) == 0) {
        sendResponse(clientSock, "ERROR:You are not a member of this group");
        return;
    }

    if (files.count(groupId) == 0 || files[groupId].count(fileName) == 0) {
        sendResponse(clientSock, "ERROR:File not found in group");
        return;
    }

    FileInfo &fInfo = files[groupId][fileName];
    
    string response = "FILEINFO|" + to_string(fInfo.fileSize) + "|" + fInfo.combinedHashes + "|";
    
    bool first = true;
    for (auto &[seederUserId, pieceMask] : fInfo.seeders) {
        if (clientAddresses.count(seederUserId) > 0) {
            if (!first) response += ";";
            first = false;
            
            ClientInfo &cInfo = clientAddresses[seederUserId];
            response += seederUserId + ":" + cInfo.ipAddr + ":" + to_string(cInfo.port) + ":";
            
            for (bool hasPiece : pieceMask) {
                response += (hasPiece ? "1" : "0");
            }
        }
    }
    
    sendResponse(clientSock, response);
}

void handleUpdatePieces(const string& groupId, const string& fileName, const string& piecesBitmap, int clientSock) {
    string userId = getLoggedInUser(clientSock);
    if (userId.empty()) {
        sendResponse(clientSock, "You must login first");
        return;
    }

    if (files.count(groupId) == 0 || files[groupId].count(fileName) == 0) {
        sendResponse(clientSock, "File not found");
        return;
    }

    FileInfo &fInfo = files[groupId][fileName];
    
    vector<bool> pieces;
    for (char c : piecesBitmap) {
        pieces.push_back(c == '1');
    }
    
    fInfo.seeders[userId] = pieces;
    
    sendResponse(clientSock, "Pieces updated successfully");
}

void handleStopShare(const string& groupId, const string& fileName, int clientSock) {
    string userId = getLoggedInUser(clientSock);
    if (userId.empty()) {
        sendResponse(clientSock, "You must login first");
        return;
    }

    if (files.count(groupId) == 0 || files[groupId].count(fileName) == 0) {
        sendResponse(clientSock, "File not found in group");
        return;
    }

    FileInfo &fInfo = files[groupId][fileName];
    
    if (fInfo.seeders.count(userId) > 0) {
        fInfo.seeders.erase(userId);
        
        if (fInfo.seeders.empty()) {
            files[groupId].erase(fileName);
        }
        
        sendResponse(clientSock, "Stopped sharing file: " + fileName);
    } else {
        sendResponse(clientSock, "You are not sharing this file");
    }
}

void handleRegisterClient(const string& userId, const string& ipAddr, const string& port, int clientSock) {
    ClientInfo cInfo;
    cInfo.ipAddr = ipAddr;
    cInfo.port = stoi(port);
    
    clientAddresses[userId] = cInfo;
    
    sendResponse(clientSock, "Client registered successfully");
}

// COMMAND EXECUTOR
void CommandExecutor(string input, int clientSock){
    vector<string> tokens = split(input, ' ');
    
    if (tokens.empty()) {
        sendResponse(clientSock, "Invalid command");
        return;
    }

    string command = tokens[0];
    
    if (command == "create_user" && tokens.size() == 3) {
        handleCreateUser(tokens[1], tokens[2], clientSock);
    }
    else if (command == "login" && tokens.size() == 3) {
        handleLogin(tokens[1], tokens[2], clientSock);
    }
    else if (command == "create_group" && tokens.size() == 2) {
        handleCreateGroup(tokens[1], clientSock);
    }
    else if (command == "join_group" && tokens.size() == 2) {
        handleJoinGroup(tokens[1], clientSock);
    }
    else if (command == "leave_group" && tokens.size() == 2) {
        handleLeaveGroup(tokens[1], clientSock);
    }
    else if (command == "list_groups" && tokens.size() == 1) {
        handleListGroups(clientSock);
    }
    else if (command == "list_requests" && tokens.size() == 2) {
        handleListRequests(tokens[1], clientSock);
    }
    else if (command == "accept_request" && tokens.size() == 3) {
        handleAcceptRequest(tokens[1], tokens[2], clientSock);
    }
    else if (command == "logout") {
        handleLogout(clientSock);
    }
    else if (command == "upload_file" && tokens.size() >= 5) {
        string hashes = "";
        for (size_t i = 4; i < tokens.size(); i++) {
            hashes += tokens[i];
            if (i < tokens.size() - 1) hashes += " ";
        }
        handleUploadFile(tokens[1], tokens[2], tokens[3], hashes, clientSock);
    }
    else if (command == "list_files" && tokens.size() == 2) {
        handleListFiles(tokens[1], clientSock);
    }
    else if (command == "get_file_info" && tokens.size() == 3) {
        handleGetFileInfo(tokens[1], tokens[2], clientSock);
    }
    else if (command == "update_pieces" && tokens.size() == 4) {
        handleUpdatePieces(tokens[1], tokens[2], tokens[3], clientSock);
    }
    else if (command == "stop_share" && tokens.size() == 3) {
        handleStopShare(tokens[1], tokens[2], clientSock);
    }
    else if (command == "register_client" && tokens.size() == 4) {
        handleRegisterClient(tokens[1], tokens[2], tokens[3], clientSock);
    }
    else {
        cout << "Unknown command" << endl;
        sendResponse(clientSock, "Unknown command");
    }
}

// HEARTBEAT & REPLICATION
void replicateCommand(const string &cmd) {
    lock_guard<mutex> lock(hbSendMutex);
    if (hbSockFd != -1) {
        string msg = "sync:" + cmd + "\n";
        ssize_t totalSent = 0;
        ssize_t msgLen = msg.size();
        
        while (totalSent < msgLen) {
            ssize_t sent = send(hbSockFd, msg.c_str() + totalSent, msgLen - totalSent, 0);
            if (sent <= 0) {
                cout << "[Replicator] Failed to send command to secondary." << endl;
                return;
            }
            totalSent += sent;
        }
        
        cout << "[Replicator] Sent cmd: " << cmd.substr(0, 50);
        if(cmd.length() > 50) cout << "... (truncated)";
        cout << endl;
    }
}

void heartBeat_Sender(const string &peerIp, int peer_port){
    try {
        while(true){
            int sockFd = socket(AF_INET, SOCK_STREAM, 0);
            if(sockFd < 0){
                throw runtime_error("Failed to connect Reciever socket");
            }
        
            sockaddr_in peer_addr{};
            peer_addr.sin_family = AF_INET;
            peer_addr.sin_port = htons(peer_port);
            inet_pton(AF_INET, peerIp.c_str(), &peer_addr.sin_addr);
            
            if(connect(sockFd, (sockaddr*)&peer_addr, sizeof(peer_addr)) == 0){
                {
                    lock_guard<mutex> lock(hbSendMutex);
                    hbSockFd = sockFd;
                }
                {
                    lock_guard<mutex> lock(state_mutex);
                    for (auto &cmd : commandLog) {
                        string msg = "sync:" + cmd + "\n";
                        send(sockFd, msg.c_str(), msg.size(), 0);
                    }
                    string done = "sync:__SYNC_DONE__\n";
                    send(sockFd, done.c_str(), done.size(), 0);
                }

                while (true) {
                    string hb = "heartbeat destination :" + to_string(peer_port) + "\n";
                    if(send(sockFd, hb.c_str(), hb.size(), 0) <= 0){
                        cout << "[Sender] connection lost. will retry .." << endl;
                        break;
                    }
                    this_thread::sleep_for(chrono::seconds(1));
                }
                {
                    lock_guard<mutex> lock(hbSendMutex);
                    hbSockFd = -1;
                }
            }
            close(sockFd);
            this_thread::sleep_for(chrono::seconds(2));
        }
    }
    catch(const std::exception& e) {
        std::cerr << e.what() << '\n';
    }
}

void heartBeatRecv(int listen_port){
    try {
        int serverFd = socket(AF_INET, SOCK_STREAM, 0);
        if(serverFd < 0){
            throw runtime_error("Unable to open connect to sender");
        }
        sockaddr_in serv_addr{};
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_addr.s_addr = INADDR_ANY;
        serv_addr.sin_port = htons(listen_port);
        int opt = 1;

        setsockopt(serverFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        if(bind(serverFd, (sockaddr*)&serv_addr, sizeof(serv_addr)) < 0){
            throw runtime_error("bind");
        }
        listen(serverFd, 5);
        cout << "[Reciver] listening for hearbeats on port  :" << listen_port << endl;

        while(true && peerAlive){
            sockaddr_in client_addr{};
            socklen_t len = sizeof(client_addr);

            int clientFd = accept(serverFd, (sockaddr *)&client_addr, &len);
            if(clientFd <= 0){
                perror("unable to recieve");
                continue;
            }
            cout << "[Reciever] Peer connected\n";

            char buffer[4096];
            string partial;
            while (true) {
                ssize_t bytes = recv(clientFd, buffer, sizeof(buffer) - 1, 0);
                if (bytes <= 0) {
                    peerAlive = false;
                    cout << "[Receiver] Lost connection to peer\n";
                    close(clientFd);
                    break;
                }
                peerAlive = true;
                buffer[bytes] = '\0';
                partial.append(buffer, bytes);

                size_t pos;
                while ((pos = partial.find('\n')) != string::npos) {
                    string line = partial.substr(0, pos);
                    partial.erase(0, pos + 1);

                    if (line.rfind("heartbeat", 0) == 0) {
                        // heartbeat received
                    }
                    else if (line.rfind("sync:", 0) == 0) {
                        string cmd = line.substr(5);
                        if (cmd == "__SYNC_DONE__") {
                            cout << "[Receiver] Initial sync complete.\n";
                        } else {
                            lock_guard<mutex> lock(state_mutex);
                            commandLog.push_back(cmd);
                            CommandExecutor(cmd, -1);
                            cout << "[Receiver] Synced cmd: " << cmd.substr(0, 50);
                            if(cmd.length() > 50) cout << "... (truncated)";
                            cout << endl;
                        }
                    }
                }
            }
        }
    }
    catch(const std::exception& e) {
        std::cerr << e.what() << '\n';
    }
}

void handleClient(int clientSock_fd, sockaddr_in clientSocAddr){
    try {
        string partialBuffer = "";
        
        while(1){
            char buffer[4096];
            ssize_t bytes = recv(clientSock_fd, buffer, sizeof(buffer) - 1, 0);
            if(bytes <= 0){
                perror("client connection failed");
                break;
            }
            buffer[bytes] = '\0';
            
            partialBuffer.append(buffer, bytes);
            
            size_t pos;
            while ((pos = partialBuffer.find('\n')) != string::npos) {
                string cmd = partialBuffer.substr(0, pos);
                partialBuffer.erase(0, pos + 1);
                
                while (!cmd.empty() && (cmd.back() == '\r')) {
                    cmd.pop_back();
                }
                
                if (cmd.empty()) continue;
                
                if(role == Tracker_role::PRIMARY){
                    appendCommandLog(cmd);
            
                    cout << "[Primary] logged & Serving client request : " << cmd.substr(0, 100);
                    if(cmd.length() > 100) cout << "... (truncated)";
                    cout << endl;
                    
                    CommandExecutor(cmd, clientSock_fd);
                    replicateCommand(cmd);
                } else {
                    cout << "[secondary] Ignoring client request" << endl;
                }
            }
        }
    }
    catch(const std::exception& e) {
        std::cerr << e.what() << '\n';
    }
    close(clientSock_fd);
}

int main(int argc, char *argv[])
{
    try {
        signal(SIGPIPE, SIG_IGN);
        if(argc != 3){
            throw runtime_error("Incorrect args");
        }
        string filepath = argv[1];
        
        vector<vector<string>> ports = getPortVector(filepath);
        
        int trackerNo = stoi(argv[2]);
        trackerNo--;

        vector<string> myIpPort = ports[trackerNo];
        vector<string> peerIpPort = ports[(trackerNo + 1) % 2];
        int port = stoi(myIpPort[1]);
        int peerPort = stoi(peerIpPort[1]);
        
        cout << "Myport " << port << " ,peerport: " << peerPort << endl;

        string ipaddr = ports[trackerNo][0];
        role = (trackerNo == 0 ? Tracker_role::PRIMARY : Tracker_role::SECONDARY);

        cout << "Tracker running on port " << port << " Role: " << ((role == Tracker_role::PRIMARY) ? "PRIMARY" : "SECONDARY") << endl;

        int sock_fd;
        sock_fd = socket(AF_INET, SOCK_STREAM, 0);
        if(sock_fd == -1){
            perror("Unable to create socket fd");
        }
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = INADDR_ANY;
        int opt = 1;
        setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        bind(sock_fd, (sockaddr *)&addr, sizeof(addr));  
        listen(sock_fd, SOMAXCONN);

        cout << "Tracker running on " << port << " ...\n";

        thread hb_thread;
        if(role == Tracker_role::PRIMARY){
            hb_thread = thread(heartBeat_Sender, peerIpPort[0], peerPort + 100);
        }else{
            hb_thread = thread(heartBeatRecv, port + 100);
        }
        hb_thread.detach();

        thread monitorThread(monitorPeer);
        monitorThread.detach();

        while(true){
            sockaddr_in clientSockAddr;
            socklen_t len = sizeof(clientSockAddr);
            int newSocket_fd = accept(sock_fd, (sockaddr*)&clientSockAddr, &len);
            if(newSocket_fd <= 0){
                this_thread::sleep_for(chrono::milliseconds(100));
            }else{
                thread(handleClient, newSocket_fd, clientSockAddr).detach();
            }   
        }
    }
    catch(const std::exception& e) {
        std::cerr << e.what() << '\n';
    }
}