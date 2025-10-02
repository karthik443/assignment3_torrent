#ifndef READFILE_H
#define READFILE_H
#include<iostream>

#include <string>
#include <vector>
#include <stdexcept>
#include <fcntl.h>
#include <unistd.h>
#include<sstream>

using namespace std;

vector<vector<string>> splitIntoPairs(const string &data, char delim) {
    vector<vector<string>> result;
    string token;
    vector<string> currentLine;

    stringstream ss(data);
    
    while(getline(ss,token,delim)){

        currentLine.push_back(token);
        if(currentLine.size()==2){
            result.push_back(currentLine);
            currentLine.clear();
        }
        
    }
    return result;
    
}

vector<vector<string>> getPortVector(const string inputFilePath) {

    int fd = open(inputFilePath.c_str(),O_RDONLY);
    if(fd==-1){
        cout<<"Unable to open file"<<endl;
        return {{}};
    }

    string content;
    char buffer[128];
    ssize_t bytesRead;
    while((bytesRead = read(fd,buffer,sizeof(buffer)))>0){
        content.append(buffer,bytesRead);
    }
    close(fd);

    if (bytesRead == -1) {

        cout<<"Unable to read file"<<endl;
        return {{}};
    }
    
    return splitIntoPairs(content, ' ');
}

vector<string> split(string input , char delim){
    string token;
    stringstream ss(input);
    vector<string>tokens;
    while(getline(ss,token,delim)){
        tokens.push_back(token);
    }
    return tokens;
}

#endif // READFILE_H
