// --- client/client.cpp (Uncommented Windows Client) ---
#include <iostream>
#include <string>
#include <cstring>
#include <fstream>
#include <sstream>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <sys/types.h>
#include <sys/stat.h>

#define PORT 8080
#define BUFFER_SIZE 4096

const std::string XOR_KEY = "mysecretkey";

std::string xor_cipher(std::string data) {
    std::string output = data;
    for (int i = 0; i < output.length(); ++i) {
        output[i] = output[i] ^ XOR_KEY[i % XOR_KEY.length()];
    }
    return output;
}

long long get_file_size(const std::string &filename) {
    std::ifstream in(filename, std::ifstream::ate | std::ifstream::binary);
    if (!in) return -1;
    return (long long)in.tellg();
}

void send_file(SOCKET sock, std::string filename, long long file_size) {
    char buffer[BUFFER_SIZE] = {0};

    memset(buffer, 0, BUFFER_SIZE);
    int bytes_read = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    if (bytes_read <= 0) {
        std::cerr << "Error: Server disconnected while waiting for READY." << std::endl;
        return;
    }
    std::string server_response = xor_cipher(std::string(buffer, bytes_read)); 

    if (server_response != "READY") {
        std::cerr << "Error: Server not ready: " << server_response << ". Aborting upload." << std::endl;
        return;
    }

    std::ifstream file_to_send(filename, std::ios::binary);
    if (!file_to_send) {
        std::cerr << "Error: Could not open file for reading: " << filename << std::endl;
        return;
    }

    long long bytes_sent = 0; 
    while (file_to_send) {
        file_to_send.read(buffer, BUFFER_SIZE);
        std::streamsize bytes_actually_read = file_to_send.gcount();
        if (bytes_actually_read > 0) {
            int sent = send(sock, buffer, (int)bytes_actually_read, 0); 
            if (sent == SOCKET_ERROR) {
                std::cerr << "Error sending data: " << WSAGetLastError() << std::endl;
                file_to_send.close();
                return;
            }
            bytes_sent += sent;
        }
    }
    file_to_send.close();
    
    memset(buffer, 0, BUFFER_SIZE);
    bytes_read = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    if (bytes_read <= 0) {
        std::cerr << "Error: Server disconnected while waiting for final response." << std::endl;
        return;
    }
    std::cout << "Server response: " << xor_cipher(std::string(buffer, bytes_read)) << std::endl;
}

void receive_file(SOCKET sock, std::string filename, long long file_size) {
    char buffer[BUFFER_SIZE] = {0};
    
    std::string encrypted_ready = xor_cipher("READY");
    send(sock, encrypted_ready.c_str(), (int)encrypted_ready.length(), 0);

    std::ofstream output_file(filename, std::ios::binary);
    if (!output_file) {
        std::cerr << "Error: Could not create file " << filename << std::endl;
        return;
    }

    long long bytes_received = 0;
    while (bytes_received < file_size) {
        int bytes_to_read = BUFFER_SIZE;
        if (file_size - bytes_received < BUFFER_SIZE) {
            bytes_to_read = (int)(file_size - bytes_received); 
        }

        int bytes_read = recv(sock, buffer, bytes_to_read, 0);
        if (bytes_read == SOCKET_ERROR) {
            std::cerr << "Error receiving data: " << WSAGetLastError() << std::endl;
            break;
        }
        if (bytes_read == 0) {
            std::cerr << "Error: Server disconnected during file transfer unexpectedly." << std::endl;
            break;
        }

        output_file.write(buffer, bytes_read);
        bytes_received += bytes_read;
    }
    output_file.close();

    if (bytes_received == file_size) {
        std::cout << "Download complete: " << filename << std::endl;
    } else {
        std::cout << "Download failed. Received " << bytes_received << " of " << file_size << " bytes." << std::endl;
    }
}

bool InitializeWinsock() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed.\n";
        return false;
    }
    return true;
}

void CleanupWinsock() {
    WSACleanup();
}

int main() {
    if (!InitializeWinsock()) {
        return 1;
    }

    SOCKET sock = INVALID_SOCKET;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE] = {0};

    if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET) {
        std::cerr << "\n Socket creation error: " << WSAGetLastError() << std::endl;
        CleanupWinsock();
        return -1;
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    
    unsigned long ip_address = inet_addr("127.0.0.1");
    if (ip_address == INADDR_NONE) {
        std::cerr << "\nInvalid address/ Address not supported \n";
        closesocket(sock);
        CleanupWinsock();
        return -1;
    }
    serv_addr.sin_addr.s_addr = ip_address;

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == SOCKET_ERROR) {
        std::cerr << "\nConnection Failed: " << WSAGetLastError() << std::endl;
        closesocket(sock);
        CleanupWinsock();
        return -1;
    }

    std::string user, pass, auth_string;
    std::cout << "Connected to secure server. Please log in." << std::endl;
    std::cout << "Username: ";
    std::getline(std::cin, user);
    std::cout << "Password: ";
    std::getline(std::cin, pass);

    auth_string = "AUTH " + user + " " + pass;
    
    std::string encrypted_auth = xor_cipher(auth_string);
    send(sock, encrypted_auth.c_str(), (int)encrypted_auth.length(), 0);

    memset(buffer, 0, BUFFER_SIZE);
    int bytes_read = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    if (bytes_read == SOCKET_ERROR || bytes_read == 0) {
        std::cerr << (bytes_read == SOCKET_ERROR ? "Auth response error: " + std::to_string(WSAGetLastError()) : "Server disconnected during authentication.") << std::endl;
        closesocket(sock);
        CleanupWinsock();
        return -1;
    }

    std::string auth_response = xor_cipher(std::string(buffer, bytes_read));

    if (auth_response.rfind("ERROR:", 0) == 0) {
        std::cerr << auth_response << std::endl;
        closesocket(sock);
        CleanupWinsock();
        return -1;
    }
    
    std::cout << auth_response << std::endl;

    std::cout << "Type 'LIST', 'GET <file>', 'PUT <file>', or 'QUIT'." << std::endl;

    while (true) {
        std::string user_input;
        std::cout << "> ";
        std::getline(std::cin, user_input);

        if (user_input.empty()) continue;

        if (user_input.rfind("PUT ", 0) == 0) {
            std::string filename = user_input.substr(4);
            long long file_size = get_file_size(filename);
            if (file_size < 0) {
                std::cout << "Error: File not found or cannot be read." << std::endl;
                continue;
            }
            
            std::string command_to_send = "PUT " + filename + " " + std::to_string(file_size);
            std::string encrypted_command = xor_cipher(command_to_send);
            send(sock, encrypted_command.c_str(), (int)encrypted_command.length(), 0);
            
            std::cout << "Uploading " << filename << " (" << file_size << " bytes)..." << std::endl;
            send_file(sock, filename, file_size);
        }
        else {
            std::string encrypted_input = xor_cipher(user_input);
            send(sock, encrypted_input.c_str(), (int)encrypted_input.length(), 0);

            if (user_input == "QUIT") {
                break;
            }

            if (user_input.rfind("GET ", 0) == 0) {
                std::string filename = user_input.substr(4);
                
                memset(buffer, 0, BUFFER_SIZE);
                bytes_read = recv(sock, buffer, BUFFER_SIZE - 1, 0);
                
                if (bytes_read == SOCKET_ERROR || bytes_read == 0) {
                    std::cout << "Server disconnected or error during GET response." << std::endl;
                    break;
                }

                std::string server_response = xor_cipher(std::string(buffer, bytes_read));
                
                if (server_response.rfind("SIZE ", 0) == 0) {
                    long long file_size = std::stoll(server_response.substr(5));
                    std::cout << "Receiving " << filename << " (" << file_size << " bytes)..." << std::endl;
                    receive_file(sock, filename, file_size);
                
                } else {
                    std::cout << "Server response: " << server_response << std::endl;
                }
            }
            else { 
                memset(buffer, 0, BUFFER_SIZE);
                bytes_read = recv(sock, buffer, BUFFER_SIZE - 1, 0);

                if (bytes_read <= 0) {
                    std::cout << "Server disconnected." << std::endl;
                    break;
                }
                std::cout << "Server response:\n" << xor_cipher(std::string(buffer, bytes_read)) << std::endl;
            }
        }
    }

    closesocket(sock);
    CleanupWinsock();
    return 0;
}