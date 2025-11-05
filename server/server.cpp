#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00     
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>           
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")


#include <iostream>
#include <string>
#include <cstring>
#include <cstddef>
#include <thread>
#include <vector>
#include <fstream>
#include <sstream>
#include <map>
#include <filesystem>
#include <sys/types.h>
#include <sys/stat.h>

#define PORT 8080
#define BUFFER_SIZE 4096

const std::string XOR_KEY = "mysecretkey";

std::string xor_cipher(const std::string &data) {
    std::string output = data;
    for (std::size_t i = 0; i < output.length(); ++i)
        output[i] ^= XOR_KEY[i % XOR_KEY.length()];
    return output;
}

std::map<std::string, std::string> users = {
    {"admin", "pass123"},
    {"Anirban", "getbetter17"}
};

bool authenticate_user(const std::string &auth_string) {
    std::stringstream ss(auth_string);
    std::string cmd, user, pass;
    ss >> cmd >> user >> pass;
    return (cmd == "AUTH" && users.count(user) && users[user] == pass);
}

long long get_file_size(const std::string &filename) {
    struct __stat64 stat_buf;
    int rc = _stat64(filename.c_str(), &stat_buf);
    return rc == 0 ? stat_buf.st_size : -1;
}

void receive_file(SOCKET sock, const std::string &filename, long long file_size) {
    char buffer[BUFFER_SIZE] = {0};
    std::filesystem::create_directory("server_files");

    std::ofstream output_file("server_files/" + filename, std::ios::binary);
    if (!output_file) {
        std::string msg = xor_cipher("ERROR: Cannot create file.");
        send(sock, msg.c_str(), (int)msg.length(), 0);
        return;
    }

    std::string ready = xor_cipher("READY");
    send(sock, ready.c_str(), (int)ready.length(), 0);

    long long bytes_received = 0;
    while (bytes_received < file_size) {
        int bytes_to_read = (int)std::min<long long>(BUFFER_SIZE, file_size - bytes_received);
        int bytes_read = recv(sock, buffer, bytes_to_read, 0);
        if (bytes_read <= 0)
            break;

        output_file.write(buffer, bytes_read);
        bytes_received += bytes_read;
    }
    output_file.close();

    std::string response = xor_cipher(bytes_received == file_size
        ? "OK: Upload successful."
        : "ERROR: Upload failed.");
    send(sock, response.c_str(), (int)response.length(), 0);
}

void handle_client(SOCKET client_socket) {
    char buffer[BUFFER_SIZE] = {0};
    bool authenticated = false;

    std::cout << "[+] Client connected. Awaiting authentication..." << std::endl;

    while (true) {
        memset(buffer, 0, BUFFER_SIZE);
        int bytes_read = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_read <= 0) {
            std::cout << "[-] Client disconnected." << std::endl;
            break;
        }

        std::string command = xor_cipher(std::string(buffer, bytes_read));
        std::cout << "[Client] " << command << std::endl;

        if (!authenticated) {
            std::string msg;
            if (authenticate_user(command)) {
                authenticated = true;
                msg = xor_cipher("OK: Auth successful. Welcome!");
                std::cout << "[+] Authentication successful." << std::endl;
            } else {
                msg = xor_cipher("ERROR: Auth failed. Invalid user/pass.");
                std::cout << "[-] Authentication failed." << std::endl;
                send(client_socket, msg.c_str(), (int)msg.length(), 0);
                break;
            }
            send(client_socket, msg.c_str(), (int)msg.length(), 0);
            continue;
        }

        if (command == "LIST") {
            std::filesystem::create_directory("server_files");
            std::string list = "Files on server:\n";
            for (auto &entry : std::filesystem::directory_iterator("server_files"))
                list += entry.path().filename().string() + "\n";
            std::string encrypted_list = xor_cipher(list);
            send(client_socket, encrypted_list.c_str(), (int)encrypted_list.length(), 0);
        }

        else if (command.rfind("GET ", 0) == 0) {
            std::string filename = command.substr(4);
            std::string filepath = "server_files/" + filename;

            if (filename.find("..") != std::string::npos) {
                std::string msg = xor_cipher("ERROR: Invalid filename.");
                send(client_socket, msg.c_str(), (int)msg.length(), 0);
                continue;
            }

            long long file_size = get_file_size(filepath);
            if (file_size < 0) {
                std::string msg = xor_cipher("ERROR: File not found.");
                send(client_socket, msg.c_str(), (int)msg.length(), 0);
                continue;
            }

            std::string msg = xor_cipher("SIZE " + std::to_string(file_size));
            send(client_socket, msg.c_str(), (int)msg.length(), 0);

            memset(buffer, 0, BUFFER_SIZE);
            recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
            if (xor_cipher(std::string(buffer)) != "READY")
                continue;

            std::ifstream file(filepath, std::ios::binary);
            while (file) {
                file.read(buffer, BUFFER_SIZE);
                std::streamsize bytes = file.gcount();
                if (bytes > 0)
                    send(client_socket, buffer, (int)bytes, 0);
            }
            file.close();
        }

        else if (command.rfind("PUT ", 0) == 0) {
            std::stringstream ss(command);
            std::string cmd, filename;
            long long file_size;
            ss >> cmd >> filename >> file_size;

            if (filename.empty() || file_size <= 0) {
                std::string msg = xor_cipher("ERROR: Bad PUT command.");
                send(client_socket, msg.c_str(), (int)msg.length(), 0);
                continue;
            }

            if (filename.find("..") != std::string::npos) {
                std::string msg = xor_cipher("ERROR: Invalid filename.");
                send(client_socket, msg.c_str(), (int)msg.length(), 0);
                continue;
            }

            receive_file(client_socket, filename, file_size);
        }

        else if (command == "QUIT") {
            std::cout << "[x] Client exited session." << std::endl;
            break;
        }

        else {
            std::string msg = xor_cipher("Unknown command.");
            send(client_socket, msg.c_str(), (int)msg.length(), 0);
        }
    }

    closesocket(client_socket);
}

int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed." << std::endl;
        return 1;
    }

    SOCKET server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_fd == INVALID_SOCKET) {
        std::cerr << "Socket creation failed: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return 1;
    }

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (sockaddr *)&address, sizeof(address)) == SOCKET_ERROR) {
        std::cerr << "Bind failed: " << WSAGetLastError() << std::endl;
        closesocket(server_fd);
        WSACleanup();
        return 1;
    }

    if (listen(server_fd, 5) == SOCKET_ERROR) {
        std::cerr << "Listen failed: " << WSAGetLastError() << std::endl;
        closesocket(server_fd);
        WSACleanup();
        return 1;
    }

    std::cout << "[SERVER] Secure server listening on port " << PORT << "..." << std::endl;

    while (true) {
        sockaddr_in client_addr{};
        int client_addr_len = sizeof(client_addr);
        SOCKET new_socket = accept(server_fd, (sockaddr *)&client_addr, &client_addr_len);

        if (new_socket == INVALID_SOCKET) {
            std::cerr << "Accept failed: " << WSAGetLastError() << std::endl;
            continue;
        }

        std::thread(handle_client, new_socket).detach();
    }

    closesocket(server_fd);
    WSACleanup();
    return 0;
}
