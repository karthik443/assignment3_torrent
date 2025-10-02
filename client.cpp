#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <stdexcept>
#include <iostream>
#include <vector>
#include <signal.h>
#include <thread>
#include <mutex>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <unordered_map>
#include <algorithm>
#include <arpa/inet.h>

#include "./readFile.h"

using namespace std;

#define PIECE_SIZE 524288  // 512KB

mutex consoleMutex;
mutex downloadMutex;
int trackerSock = -1;
string myUserId;
string myIpAddr;
int myPort;

struct DownloadInfo {
    string groupId;
    string fileName;
    string destPath;
    long long fileSize;
    vector<string> pieceHashes;
    vector<bool> piecesDownloaded;
    bool isComplete;
    int totalPieces;
};

struct SeederInfo {
    string userId;
    string ipAddr;
    int port;
    vector<bool> availablePieces;
};

unordered_map<string, DownloadInfo> activeDownloads; // key: groupId:fileName

int connectToTracker(string hostname, vector<vector<string>> ports) {
    for (auto ip_port : ports) {
        int sock_fd;
        sockaddr_in serv_addr;
        hostent* server = gethostbyname(ip_port[0].c_str());
        if (!server) {
            perror("Unable to find hostname");
            continue;
        }

        sock_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (sock_fd < 0) continue;

        bzero((char*)&serv_addr, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        bcopy((char*)server->h_addr, (char*)&serv_addr.sin_addr.s_addr, server->h_length);
        serv_addr.sin_port = htons(stoi(ip_port[1]));

        if (connect(sock_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == 0) {
            cout << "[CLIENT] Connected to the tracker on Port: " << ip_port[1] << endl;
            return sock_fd;
        }

        close(sock_fd);
    }

    throw runtime_error("Unable to connect to any tracker");
}

string calculateSHA1(const char* data, size_t length) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1((unsigned char*)data, length, hash);
    
    char hexHash[SHA_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        sprintf(hexHash + (i * 2), "%02x", hash[i]);
    }
    hexHash[SHA_DIGEST_LENGTH * 2] = '\0';
    
    return string(hexHash);
}

string calculateFileSHA1(const string& filePath) {
    int fd = open(filePath.c_str(), O_RDONLY);
    if (fd < 0) {
        throw runtime_error("Cannot open file for hashing");
    }

    SHA_CTX shaContext;
    SHA1_Init(&shaContext);

    char buffer[8192];
    ssize_t bytesRead;
    while ((bytesRead = read(fd, buffer, sizeof(buffer))) > 0) {
        SHA1_Update(&shaContext, buffer, bytesRead);
    }

    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1_Final(hash, &shaContext);
    close(fd);

    char hexHash[SHA_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        sprintf(hexHash + (i * 2), "%02x", hash[i]);
    }
    hexHash[SHA_DIGEST_LENGTH * 2] = '\0';

    return string(hexHash);
}

vector<string> calculatePieceHashes(const string& filePath) {
    vector<string> hashes;
    int fd = open(filePath.c_str(), O_RDONLY);
    if (fd < 0) {
        throw runtime_error("Cannot open file for piece hashing");
    }

    char buffer[PIECE_SIZE];
    ssize_t bytesRead;
    
    while ((bytesRead = read(fd, buffer, PIECE_SIZE)) > 0) {
        string hash = calculateSHA1(buffer, bytesRead);
        hashes.push_back(hash);
    }

    close(fd);
    return hashes;
}

void sendToTracker(const string& message) {
    if (trackerSock != -1) {
        string msg = message + "\n";
        ssize_t totalSent = 0;
        ssize_t msgLen = msg.size();
        
        // Send the entire message, handling partial sends
        while (totalSent < msgLen) {
            ssize_t sent = send(trackerSock, msg.c_str() + totalSent, msgLen - totalSent, 0);
            if (sent <= 0) {
                cout << "[CLIENT] Failed to send to tracker\n";
                return;
            }
            totalSent += sent;
        }
    }
}

string receiveFromTracker() {
    char buffer[8192];
    string result = "";
    
    // Keep reading until we get a complete line (ends with newline)
    while (true) {
        bzero(buffer, sizeof(buffer));
        int n = read(trackerSock, buffer, sizeof(buffer) - 1);
        if (n < 0) {
            return "ERROR:Connection lost";
        }
        if (n == 0) {
            break;
        }
        
        result.append(buffer, n);
        
        // Check if we got a complete message (ends with newline)
        if (result.find('\n') != string::npos) {
            break;
        }
    }
    
    // Remove trailing newline
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r')) {
        result.pop_back();
    }
    
    return result;
}

void handleUploadFile(const vector<string>& tokens) {
    if (tokens.size() != 3) {
        cout << "Usage: upload_file <group_id> <file_path>\n";
        return;
    }

    string groupId = tokens[1];
    string filePath = tokens[2];

    // Check if file exists
    struct stat fileStat;
    if (stat(filePath.c_str(), &fileStat) != 0) {
        cout << "File does not exist: " << filePath << endl;
        return;
    }

    long long fileSize = fileStat.st_size;
    
    // Extract filename from path
    string fileName = filePath;
    size_t lastSlash = filePath.find_last_of("/\\");
    if (lastSlash != string::npos) {
        fileName = filePath.substr(lastSlash + 1);
    }

    cout << "Calculating hashes for file: " << fileName << " (" << fileSize << " bytes)...\n";

    // Calculate piece hashes
    vector<string> pieceHashes = calculatePieceHashes(filePath);
    
    // Combine all hashes into single string
    string combinedHashes = "";
    for (size_t i = 0; i < pieceHashes.size(); i++) {
        combinedHashes += pieceHashes[i];
        if (i < pieceHashes.size() - 1) {
            combinedHashes += ",";
        }
    }

    // Send to tracker
    string cmd = "upload_file " + groupId + " " + fileName + " " + to_string(fileSize) + " " + combinedHashes;
    sendToTracker(cmd);
    
    string response = receiveFromTracker();
    cout << response << endl;

    if (response.find("successfully") != string::npos) {
        // Store local file info for serving
        string key = groupId + ":" + fileName;
        DownloadInfo dInfo;
        dInfo.groupId = groupId;
        dInfo.fileName = fileName;
        dInfo.destPath = filePath;
        dInfo.fileSize = fileSize;
        dInfo.pieceHashes = pieceHashes;
        dInfo.totalPieces = pieceHashes.size();
        dInfo.piecesDownloaded.resize(dInfo.totalPieces, true);
        dInfo.isComplete = true;
        
        lock_guard<mutex> lock(downloadMutex);
        activeDownloads[key] = dInfo;
    }
}

void handleListFiles(const vector<string>& tokens) {
    if (tokens.size() != 2) {
        cout << "Usage: list_files <group_id>\n";
        return;
    }

    string cmd = "list_files " + tokens[1];
    sendToTracker(cmd);
    
    string response = receiveFromTracker();
    cout << response << endl;
}

vector<SeederInfo> parseFileInfo(const string& response, long long& fileSize, vector<string>& pieceHashes) {
    vector<SeederInfo> seeders;
    
    // Format: FILEINFO|filesize|hash1,hash2,...|seeder1:ip:port:bitmap;seeder2:ip:port:bitmap;...
    vector<string> parts = split(response, '|');
    if (parts.size() < 4 || parts[0] != "FILEINFO") {
        return seeders;
    }

    fileSize = stoll(parts[1]);
    
    // Parse hashes
    pieceHashes = split(parts[2], ',');
    
    // Parse seeders
    vector<string> seederStrs = split(parts[3], ';');
    for (const string& seederStr : seederStrs) {
        if (seederStr.empty()) continue;
        
        vector<string> seederParts = split(seederStr, ':');
        if (seederParts.size() != 4) continue;
        
        SeederInfo sInfo;
        sInfo.userId = seederParts[0];
        sInfo.ipAddr = seederParts[1];
        sInfo.port = stoi(seederParts[2]);
        
        // Parse bitmap
        string bitmap = seederParts[3];
        for (char c : bitmap) {
            sInfo.availablePieces.push_back(c == '1');
        }
        
        seeders.push_back(sInfo);
    }
    
    return seeders;
}

int connectToPeer(const string& ipAddr, int port) {
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        return -1;
    }

    sockaddr_in peer_addr;
    bzero((char*)&peer_addr, sizeof(peer_addr));
    peer_addr.sin_family = AF_INET;
    inet_pton(AF_INET, ipAddr.c_str(), &peer_addr.sin_addr);
    peer_addr.sin_port = htons(port);

    if (connect(sock_fd, (struct sockaddr*)&peer_addr, sizeof(peer_addr)) < 0) {
        close(sock_fd);
        return -1;
    }

    return sock_fd;
}

bool downloadPieceFromPeer(const string& ipAddr, int port, const string& groupId, 
                           const string& fileName, int pieceIndex, const string& destPath,
                           const string& expectedHash) {
    int peerSock = connectToPeer(ipAddr, port);
    if (peerSock < 0) {
        return false;
    }

    // Request piece: GET_PIECE|groupId|fileName|pieceIndex
    string request = "GET_PIECE|" + groupId + "|" + fileName + "|" + to_string(pieceIndex) + "\n";
    send(peerSock, request.c_str(), request.size(), 0);

    // Receive piece data
    char buffer[PIECE_SIZE];
    ssize_t totalReceived = 0;
    
    // Set a timeout for receiving
    struct timeval tv;
    tv.tv_sec = 10;  // 10 second timeout
    tv.tv_usec = 0;
    setsockopt(peerSock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    // Keep receiving until we have enough data or connection closes
    while (totalReceived < PIECE_SIZE) {
        ssize_t bytesReceived = recv(peerSock, buffer + totalReceived, PIECE_SIZE - totalReceived, 0);
        
        if (bytesReceived < 0) {
            close(peerSock);
            return false;
        }
        
        if (bytesReceived == 0) {
            // Connection closed, we got all the data
            break;
        }
        
        totalReceived += bytesReceived;
        
        // Check if we received an error message (should be small and contain newline)
        if (totalReceived < 100) {
            for (ssize_t i = 0; i < totalReceived; i++) {
                if (buffer[i] == '\n') {
                    close(peerSock);
                    return false;
                }
            }
        }
    }

    close(peerSock);

    if (totalReceived <= 0) {
        return false;
    }

    // Verify hash
    string actualHash = calculateSHA1(buffer, totalReceived);
    if (actualHash != expectedHash) {
        cout << "[DOWNLOAD] Hash mismatch for piece " << pieceIndex 
             << " (expected: " << expectedHash.substr(0, 8) << "..., got: " << actualHash.substr(0, 8) << "...)" << endl;
        return false;
    }

    // Write piece to file
    int fd = open(destPath.c_str(), O_WRONLY | O_CREAT, 0644);
    if (fd < 0) {
        return false;
    }

    lseek(fd, (long long)pieceIndex * PIECE_SIZE, SEEK_SET);
    write(fd, buffer, totalReceived);
    close(fd);

    return true;
}

void downloadFileThread(string groupId, string fileName, string destPath) {
    string key = groupId + ":" + fileName;
    
    // Get file info from tracker
    string cmd = "get_file_info " + groupId + " " + fileName;
    sendToTracker(cmd);
    
    string response = receiveFromTracker();
    
    if (response.find("ERROR") != string::npos) {
        lock_guard<mutex> lock(consoleMutex);
        cout << response << endl;
        return;
    }

    long long fileSize;
    vector<string> pieceHashes;
    vector<SeederInfo> seeders = parseFileInfo(response, fileSize, pieceHashes);

    if (seeders.empty()) {
        lock_guard<mutex> lock(consoleMutex);
        cout << "[DOWNLOAD] No seeders available for " << fileName << endl;
        return;
    }

    // Initialize download info
    DownloadInfo dInfo;
    dInfo.groupId = groupId;
    dInfo.fileName = fileName;
    dInfo.destPath = destPath;
    dInfo.fileSize = fileSize;
    dInfo.pieceHashes = pieceHashes;
    dInfo.totalPieces = pieceHashes.size();
    dInfo.piecesDownloaded.resize(dInfo.totalPieces, false);
    dInfo.isComplete = false;

    {
        lock_guard<mutex> lock(downloadMutex);
        activeDownloads[key] = dInfo;
    }

    {
        lock_guard<mutex> lock(consoleMutex);
        cout << "[DOWNLOAD] Starting download of " << fileName << " (" << dInfo.totalPieces << " pieces)\n";
    }

    // Download pieces
    int downloadedCount = 0;
    for (int pieceIdx = 0; pieceIdx < dInfo.totalPieces; pieceIdx++) {
        bool downloaded = false;
        
        // Try each seeder
        for (const SeederInfo& seeder : seeders) {
            if (pieceIdx < (int)seeder.availablePieces.size() && seeder.availablePieces[pieceIdx]) {
                if (downloadPieceFromPeer(seeder.ipAddr, seeder.port, groupId, fileName, 
                                         pieceIdx, destPath, pieceHashes[pieceIdx])) {
                    downloaded = true;
                    downloadedCount++;
                    
                    {
                        lock_guard<mutex> lock(downloadMutex);
                        activeDownloads[key].piecesDownloaded[pieceIdx] = true;
                    }
                    
                    {
                        lock_guard<mutex> lock(consoleMutex);
                        cout << "[DOWNLOAD] Downloaded piece " << pieceIdx + 1 << "/" << dInfo.totalPieces 
                             << " of " << fileName << endl;
                    }
                    
                    break;
                }
            }
        }
        
        if (!downloaded) {
            lock_guard<mutex> lock(consoleMutex);
            cout << "[DOWNLOAD] Failed to download piece " << pieceIdx << " from any seeder\n";
        }
    }

    if (downloadedCount == dInfo.totalPieces) {
        {
            lock_guard<mutex> lock(downloadMutex);
            activeDownloads[key].isComplete = true;
        }
        
        {
            lock_guard<mutex> lock(consoleMutex);
            cout << "[C] [" << groupId << "] " << fileName << endl;
        }

        // Update tracker with our pieces
        string bitmap = "";
        for (bool b : dInfo.piecesDownloaded) {
            bitmap += (b ? "1" : "0");
        }
        string updateCmd = "update_pieces " + groupId + " " + fileName + " " + bitmap;
        sendToTracker(updateCmd);
        receiveFromTracker();
    } else {
        lock_guard<mutex> lock(consoleMutex);
        cout << "[DOWNLOAD] Incomplete download of " << fileName << " (" << downloadedCount 
             << "/" << dInfo.totalPieces << " pieces)\n";
    }
}

void handleDownloadFile(const vector<string>& tokens) {
    if (tokens.size() != 4) {
        cout << "Usage: download_file <group_id> <file_name> <destination_path>\n";
        return;
    }

    string groupId = tokens[1];
    string fileName = tokens[2];
    string destPath = tokens[3];

    thread(downloadFileThread, groupId, fileName, destPath).detach();
}

void handleShowDownloads() {
    lock_guard<mutex> lock(downloadMutex);
    
    if (activeDownloads.empty()) {
        cout << "No active downloads\n";
        return;
    }

    cout << "Active Downloads:\n";
    for (const auto& [key, dInfo] : activeDownloads) {
        int completed = 0;
        for (bool b : dInfo.piecesDownloaded) {
            if (b) completed++;
        }
        
        string status = dInfo.isComplete ? "[C]" : "[D]";
        cout << status << " [" << dInfo.groupId << "] " << dInfo.fileName 
             << " - " << completed << "/" << dInfo.totalPieces << " pieces\n";
    }
}

void handleStopShare(const vector<string>& tokens) {
    if (tokens.size() != 3) {
        cout << "Usage: stop_share <group_id> <file_name>\n";
        return;
    }

    string cmd = "stop_share " + tokens[1] + " " + tokens[2];
    sendToTracker(cmd);
    
    string response = receiveFromTracker();
    cout << response << endl;

    // Remove from local tracking
    string key = tokens[1] + ":" + tokens[2];
    lock_guard<mutex> lock(downloadMutex);
    activeDownloads.erase(key);
}

void servePiece(int clientSock, const string& groupId, const string& fileName, int pieceIndex) {
    string key = groupId + ":" + fileName;
    
    DownloadInfo dInfo;
    {
        lock_guard<mutex> lock(downloadMutex);
        if (activeDownloads.count(key) == 0) {
            string error = "ERROR:File not found\n";
            send(clientSock, error.c_str(), error.size(), 0);
            return;
        }
        dInfo = activeDownloads[key];
    }

    if (pieceIndex >= dInfo.totalPieces || !dInfo.piecesDownloaded[pieceIndex]) {
        string error = "ERROR:Piece not available\n";
        send(clientSock, error.c_str(), error.size(), 0);
        return;
    }

    // Read piece from file
    int fd = open(dInfo.destPath.c_str(), O_RDONLY);
    if (fd < 0) {
        string error = "ERROR:Cannot open file\n";
        send(clientSock, error.c_str(), error.size(), 0);
        return;
    }

    lseek(fd, (long long)pieceIndex * PIECE_SIZE, SEEK_SET);
    
    char buffer[PIECE_SIZE];
    ssize_t bytesRead = read(fd, buffer, PIECE_SIZE);
    close(fd);

    if (bytesRead > 0) {
        // Send the entire piece, handling partial sends
        ssize_t totalSent = 0;
        while (totalSent < bytesRead) {
            ssize_t sent = send(clientSock, buffer + totalSent, bytesRead - totalSent, 0);
            if (sent <= 0) {
                break;
            }
            totalSent += sent;
        }
    } else {
        string error = "ERROR:Failed to read piece\n";
        send(clientSock, error.c_str(), error.size(), 0);
    }
}

void handlePeerClient(int clientSock) {
    char buffer[256];
    ssize_t bytes = recv(clientSock, buffer, sizeof(buffer) - 1, 0);
    
    if (bytes <= 0) {
        close(clientSock);
        return;
    }
    
    buffer[bytes] = '\0';
    string request(buffer);
    
    // Remove newline
    if (!request.empty() && request.back() == '\n') {
        request.pop_back();
    }

    // Format: GET_PIECE|groupId|fileName|pieceIndex
    vector<string> parts = split(request, '|');
    if (parts.size() == 4 && parts[0] == "GET_PIECE") {
        string groupId = parts[1];
        string fileName = parts[2];
        int pieceIndex = stoi(parts[3]);
        
        servePiece(clientSock, groupId, fileName, pieceIndex);
    }
    
    close(clientSock);
}

void startPeerServer(int port) {
    int serverFd = socket(AF_INET, SOCK_STREAM, 0);
    if (serverFd < 0) {
        cerr << "Failed to create peer server socket\n";
        return;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    int opt = 1;
    setsockopt(serverFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    if (bind(serverFd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        cerr << "Failed to bind peer server\n";
        close(serverFd);
        return;
    }
    
    listen(serverFd, SOMAXCONN);
    cout << "[PEER SERVER] Listening on port " << port << endl;

    while (true) {
        sockaddr_in clientAddr;
        socklen_t len = sizeof(clientAddr);
        int clientSock = accept(serverFd, (sockaddr*)&clientAddr, &len);
        
        if (clientSock > 0) {
            thread(handlePeerClient, clientSock).detach();
        }
    }
}

int main(int argc, char* argv[]) {
    try {
        signal(SIGPIPE, SIG_IGN);

        if (argc < 3) {
            throw runtime_error("Usage: ./client <IP>:<PORT> <tracker_info_file>");
        }

        string clientIp_port = argv[1];
        string filepath = argv[2];
        
        vector<vector<string>> ports = getPortVector(filepath);
        string hostname = ports[0][0];

        // Parse client IP and port
        vector<string> ipPortVector = split(clientIp_port, ':');
        myIpAddr = ipPortVector[0];
        myPort = stoi(ipPortVector[1]);

        // Connect to tracker
        trackerSock = connectToTracker(hostname, ports);

        // Start peer server
        thread peerServerThread(startPeerServer, myPort);
        peerServerThread.detach();

        // Wait a bit for server to start
        this_thread::sleep_for(chrono::milliseconds(500));

        cout << "Client ready. Type commands (or 'exit' to quit)\n";

        while (true) {
            printf("> ");
            char buffer[1024];
            bzero(buffer, 1024);
            
            if (!fgets(buffer, 1023, stdin)) {
                break;
            }

            size_t len = strlen(buffer);
            if (len > 0 && buffer[len - 1] == '\n') {
                buffer[len - 1] = '\0';
            }

            string input(buffer);
            if (input == "exit" || input == "quit") {
                break;
            }

            vector<string> tokens = split(input, ' ');
            if (tokens.empty()) continue;

            string command = tokens[0];

            // Handle file commands locally
            if (command == "upload_file") {
                handleUploadFile(tokens);
            } else if (command == "list_files") {
                handleListFiles(tokens);
            } else if (command == "download_file") {
                handleDownloadFile(tokens);
            } else if (command == "show_downloads") {
                handleShowDownloads();
            } else if (command == "stop_share") {
                handleStopShare(tokens);
            } else if (command == "login" && tokens.size() == 3) {
                // After login, register our address with tracker
                sendToTracker(input);
                string response = receiveFromTracker();
                cout << response << endl;
                
                if (response.find("successful") != string::npos) {
                    myUserId = tokens[1];
                    string registerCmd = "register_client " + myUserId + " " + myIpAddr + " " + to_string(myPort);
                    sendToTracker(registerCmd);
                    receiveFromTracker();
                }
            } else {
                // Send other commands to tracker
                sendToTracker(input);
                string response = receiveFromTracker();
                cout << response << endl;
            }
        }

        close(trackerSock);
    }
    catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
    }

    return 0;
}