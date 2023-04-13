#pragma once
#include <string>
#include "utils.h"
#include <cpr/api.h>
#include <nlohmann/json.hpp>
#include <typeinfo>
#include <iostream>
#include <chrono>
#include <ctime>
#include <fstream>
#include <algorithm>
#include <Windows.h>
#include <cstdio>
#include <cstdlib>
#include <iomanip>
#include <sstream>
#include <ctime>
#include <openssl/md5.h>
namespace json = nlohmann;
using namespace std;

namespace API
{
    namespace Constants
    {
        std::string apiUrl = "https://api.blitzware.xyz/api/";
        bool initialized = false;
        bool started = false;
        bool breached = false;
        auto timeSent = time(NULL);
    };

    std::string exec(const char* cmd) {
        std::array<char, 128> buffer{};
        std::string result;
        //#ifdef OS_WINDOWS
        std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen(cmd, "r"), _pclose);
        //#else
        //std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
        //#endif
        if (!pipe) {
            throw std::runtime_error("popen() failed!");
        }
        while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
            result += buffer.data();
        }
        return result;
    }

    std::vector<std::string> split(const std::string& str,
        const std::string& delimiter) {
        std::vector<std::string> output;
        std::string s = str;

        size_t pos = 0;
        std::string token;
        while ((pos = s.find(delimiter)) != std::string::npos) {
            token = s.substr(0, pos);
            output.push_back(token);
            s.erase(0, pos + delimiter.length());
        }

        output.push_back(s);
        return output;
    }

    std::string strip(const std::string& str,
        const std::function<bool(const char)>& callback) {
        auto start_it = str.begin();
        auto end_it = str.rbegin();
        while (callback(*start_it) && start_it != end_it.base())
            ++start_it;
        while (callback(*end_it) && start_it != end_it.base())
            ++end_it;
        return std::string(start_it, end_it.base());
    }

    std::string HWID() {
        std::string hwid;

        //#ifdef OS_WINDOWS
        hwid = split(exec("wmic csproduct get uuid"), "\n")[1];
        //#else
        //hwid = exec("dmidecode -s system-uuid");
        //#endif

        return strip(hwid, [](const char c) { return std::isspace(c); });
    }

    std::string IP() {
        auto response = cpr::Get // or cpr::Head
        (
            cpr::Url{ "http://icanhazip.com" },
            cpr::Header{ {"accept", "text/html"} },
            cpr::Timeout{ 4 * 1000 }
        );
        return response.text;
    }

    namespace ApplicationSettings
    {
        std::string id;
        bool status;
        bool hwidCheck;
        bool developerMode;
        bool integrityCheck;
        std::string programHash;
        std::string version;
        std::string downloadLink;
        auto freeMode = NULL;
        auto login = NULL;
        auto name = NULL;
        auto registerd = NULL;
        auto TotalUsers = NULL;
    };
    namespace User
    {
        std::string ID;
        std::string Username;
        std::string Pasword;
        std::string Email;
        std::string HWID;
        std::string IP;
        std::string Expiry;
        std::string LastLogin;
        std::string RegisterDate;
    };

    class Security {
    public:
        static void Start() {
            char drive[MAX_PATH];
            _splitpath_s(getenv("SystemRoot"), NULL, 0, drive, MAX_PATH, NULL, 0, NULL, 0);

            if (Constants::started) {
                MessageBoxA(NULL, "A session has already been started, please end the previous one!", "Security", MB_OK | MB_ICONWARNING);
                ExitProcess(0);
            }
            else {
                string hosts_path = drive;
                hosts_path += "Windows\\System32\\drivers\\etc\\hosts";
                ifstream hosts_file(hosts_path.c_str());

                if (hosts_file.is_open()) {
                    string contents((istreambuf_iterator<char>(hosts_file)), istreambuf_iterator<char>());
                    if (contents.find("api.blitzware.xyz") != string::npos) {
                        Constants::breached = true;
                        MessageBoxA(NULL, "DNS redirecting has been detected!", "Security", MB_OK | MB_ICONERROR);
                        ExitProcess(0);
                    }
                }
                Constants::started = true;
            }
        }

        static void End() {
            if (!Constants::started) {
                MessageBoxA(NULL, "No session has been started, closing for security reasons!", "Security", MB_OK | MB_ICONWARNING);
                ExitProcess(0);
            }
            else {
                Constants::started = false;
            }
        }

        static string Integrity(const char* filename) {
            string result;
            ifstream file(filename, ios::binary);

            if (file.is_open()) {
                file.seekg(0, ios::end);
                streampos size = file.tellg();
                char* buffer = new char[size];
                file.seekg(0, ios::beg);
                file.read(buffer, size);
                file.close();

                unsigned char hash[MD5_DIGEST_LENGTH];
                MD5((unsigned char*)buffer, size, hash);

                stringstream ss;
                for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
                    ss << setfill('0') << setw(2) << hex << (int)hash[i];
                }
                result = ss.str();
                delete[] buffer;
            }
            return result;
        }

        static bool MaliciousCheck(time_t date) {
            time_t t = time(NULL);
            double diff = difftime(t, date);
            if (diff >= 5 || abs(diff) >= 60) {
                Constants::breached = true;
                return true;
            }
            else {
                return false;
            }
        }
    };

    namespace OnProgramStart
    {
        LPCSTR Name;

        void Initialize(std::string name, std::string secret, std::string version)
        {
            try
            {
                Security::Start();
                json::json AppInitDetails;
                AppInitDetails["name"] = name;
                AppInitDetails["secret"] = secret;
                AppInitDetails["version"] = version;
                auto response = cpr::Post(cpr::Url{ Constants::apiUrl + "applications/initialize" },
                    cpr::Body{ AppInitDetails.dump() },
                    cpr::Header{ {"Content-Type", "application/json"} });
                json::json content;

                if (Security::MaliciousCheck(Constants::timeSent))
                {
                    MessageBoxA(NULL, "Possible malicious activity detected!", OnProgramStart::Name, MB_ICONEXCLAMATION | MB_OK);
                    exit(0);
                }
                if (Constants::breached)
                {
                    MessageBoxA(NULL, "Possible malicious activity detected!", OnProgramStart::Name, MB_ICONEXCLAMATION | MB_OK);
                    exit(0);
                }

                if (response.status_code == 200)
                {
                    content = json::json::parse(response.text);
                    Constants::initialized = true;
                    ApplicationSettings::id = Utilities::removeQuotesFromString(to_string(content["id"]));
                    ApplicationSettings::status = content["status"] == 1 ? true : false;
                    ApplicationSettings::hwidCheck = content["hwidCheck"] == 1 ? true : false;
                    ApplicationSettings::integrityCheck = content["integrityCheck"] == 1 ? true : false;
                    ApplicationSettings::programHash = Utilities::removeQuotesFromString(to_string(content["programHash"]));
                    ApplicationSettings::version = Utilities::removeQuotesFromString(to_string(content["version"]));
                    ApplicationSettings::downloadLink = Utilities::removeQuotesFromString(to_string(content["downloadLink"]));
                    ApplicationSettings::developerMode = content["developerMode"] == 1 ? true : false;
                    ApplicationSettings::freeMode = content["freeMode"] == 1 ? true : false;

                    if (API::ApplicationSettings::freeMode)
                        MessageBoxA(NULL, "Application is in Free Mode!", OnProgramStart::Name,
                            MB_ICONINFORMATION | MB_OK);

                    if (API::ApplicationSettings::developerMode) 
                    {
                        MessageBoxA(NULL, "Application is in Developer Mode, bypassing integrity and update check!", OnProgramStart::Name, MB_OK | MB_ICONWARNING);
                   
                        // Get the full path of the current executable
                        WCHAR buffer[MAX_PATH];
                        GetModuleFileName(NULL, buffer, MAX_PATH);
                        // Convert the wide character string to a regular string
                        char fullPath[MAX_PATH];
                        wcstombs(fullPath, buffer, MAX_PATH);
                        // Get the directory path of the current file
                        string dirPath = string(fullPath);
                        dirPath = dirPath.substr(0, dirPath.find_last_of("\\/"));

                        ofstream integrity_log("integrity.txt");
                        if (integrity_log.is_open()) {
                            std::string hash = Security::Integrity(fullPath);
                            integrity_log << hash << endl;
                            integrity_log.close();
                            MessageBoxA(NULL, "Your application's hash has been saved to integrity.txt, please refer to this when your application is ready for release!", OnProgramStart::Name, MB_OK | MB_ICONINFORMATION);
                        }
                    }
                    else
                    {
                        if (ApplicationSettings::version != version)
                        {
                            MessageBoxA(NULL, "Update is available, redirecting to update!", OnProgramStart::Name,
                                MB_ICONERROR | MB_OK);
                            system(std::string("start " + ApplicationSettings::downloadLink).c_str());
                            exit(0);
                        }
                        if (ApplicationSettings::integrityCheck)
                        {
                            // Get the full path of the current executable
                            WCHAR buffer[MAX_PATH];
                            GetModuleFileName(NULL, buffer, MAX_PATH);
                            // Convert the wide character string to a regular string
                            char fullPath[MAX_PATH];
                            wcstombs(fullPath, buffer, MAX_PATH);
                            // Get the directory path of the current file
                            string dirPath = string(fullPath);
                            dirPath = dirPath.substr(0, dirPath.find_last_of("\\/"));

                            if (ApplicationSettings::programHash != Security::Integrity(fullPath))
                            {
                                MessageBoxA(NULL, "File has been tampered with, couldn't verify integrity!", OnProgramStart::Name,
                                    MB_ICONERROR | MB_OK);
                                exit(0);
                            }
                        }
                    }
                    if (ApplicationSettings::status == false)
                    {
                        MessageBoxA(NULL, "Looks like this application is disabled, please try again later!", OnProgramStart::Name,
                            MB_ICONERROR | MB_OK);
                        exit(0);
                    }
                }
                else
                {
                    content = json::json::parse(response.text);
                    if (response.status_code == 0)
                    {
                        MessageBoxA(NULL, "Unable to connect to the remote server!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
                        exit(0);
                    }
                    if (Utilities::removeQuotesFromString(to_string(content["code"])) == "NOT_FOUND")
                    {
                        MessageBoxA(NULL, "Application does not exist!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
                        exit(0);
                    }
                    else if (Utilities::removeQuotesFromString(to_string(content["code"])) == "VALIDATION_FAILED")
                    {
                        MessageBoxA(NULL, "Failed to initialize your application correctly!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
                        exit(0);
                    }
                }
                Security::End();
            }
            catch (const std::exception& ex)
            {
                MessageBoxA(NULL, "Unkown error, contact support!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
                std::cout << ex.what() << std::endl;
            }
        }
    };

    static bool Login(std::string username, std::string password)
    {
        if (!Constants::initialized)
        {
            MessageBoxA(NULL, "Please initialize your application first!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
            return false;
        }
        try
        {
            Security::Start();
            Constants::timeSent = time(NULL);
            json::json UserLoginDetails;
            UserLoginDetails["username"] = username;
            UserLoginDetails["password"] = password;
            UserLoginDetails["hwid"] = HWID();
            UserLoginDetails["lastIP"] = IP();
            auto response = cpr::Post(cpr::Url{ Constants::apiUrl + "users/login" },
                cpr::Body{ UserLoginDetails.dump() },
                cpr::Header{ {"Content-Type", "application/json"} });
            json::json content;

            if (Security::MaliciousCheck(Constants::timeSent))
            {
                MessageBoxA(NULL, "Possible malicious activity detected!", OnProgramStart::Name, MB_ICONEXCLAMATION | MB_OK);
                exit(0);
            }
            if (Constants::breached)
            {
                MessageBoxA(NULL, "Possible malicious activity detected!", OnProgramStart::Name, MB_ICONEXCLAMATION | MB_OK);
                exit(0);
            }

            if (response.status_code == 200 || response.status_code == 201)
            {
                content = json::json::parse(response.text);
                User::ID = Utilities::removeQuotesFromString(to_string(content["id"]));
                User::Username = Utilities::removeQuotesFromString(to_string(content["username"]));
                User::Pasword = Utilities::removeQuotesFromString(to_string(content["password"]));
                User::Email = Utilities::removeQuotesFromString(to_string(content["email"]));
                User::Expiry = Utilities::removeQuotesFromString(to_string(content["expiryDate"]));
                User::LastLogin = Utilities::removeQuotesFromString(to_string(content["lastLogin"]));
                User::IP = Utilities::removeQuotesFromString(to_string(content["lastIP"]));
                User::HWID = Utilities::removeQuotesFromString(to_string(content["hwid"]));
                Security::End();
                return true;
            }
            else
            {
                content = json::json::parse(response.text);
                if (response.status_code == 0)
                {
                    MessageBoxA(NULL, "Unable to connect to the remote server!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
                    Security::End();
                    return false;
                }
                if (Utilities::removeQuotesFromString(to_string(content["code"])) == "NOT_FOUND")
                {
                    MessageBoxA(NULL, "The given username does not exist!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
                }
                else if (Utilities::removeQuotesFromString(to_string(content["code"])) == "VALIDATION_FAILED")
                {
                    MessageBoxA(NULL, "Missing user login information!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
                }
                else if (Utilities::removeQuotesFromString(to_string(content["code"])) == "UNAUTHORIZED")
                {
                    if (Utilities::removeQuotesFromString(to_string(content["message"])) == "The given username and password do not match!")
                    {
                        MessageBoxA(NULL, "The given username and password do not match!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
                    }
                    else if (Utilities::removeQuotesFromString(to_string(content["message"])) == "Your subscription has expired!")
                    {
                        MessageBoxA(NULL, "Your subscription has expired!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
                    }
                    else if (Utilities::removeQuotesFromString(to_string(content["message"])) == "Your HWID does not match!")
                    {
                        MessageBoxA(NULL, "Your HWID does not match!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
                    }
                }
                Security::End();
                return false;
            }
        }
        catch (const std::exception& ex)
        {
            MessageBoxA(NULL, "Unkown error, contact support!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
            std::cout << ex.what() << std::endl;
            Security::End();
            return false;
        }
    }

    static bool Register(std::string username, std::string password, std::string email, std::string license)
    {
        if (!Constants::initialized)
        {
            MessageBoxA(NULL, "Please initialize your application first!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
            return false;
        }
        try
        {
            Security::Start();
            Constants::timeSent = time(NULL);
            json::json UserRegisterDetails;
            UserRegisterDetails["username"] = username;
            UserRegisterDetails["password"] = password;
            UserRegisterDetails["email"] = email;
            UserRegisterDetails["license"] = license;
            UserRegisterDetails["hwid"] = HWID();
            UserRegisterDetails["lastIP"] = IP();
            UserRegisterDetails["id"] = ApplicationSettings::id;
            auto response = cpr::Post(cpr::Url{ Constants::apiUrl + "users/register" },
                cpr::Body{ UserRegisterDetails.dump() },
                cpr::Header{ {"Content-Type", "application/json"} });
            json::json content;

            if (Security::MaliciousCheck(Constants::timeSent))
            {
                MessageBoxA(NULL, "Possible malicious activity detected!", OnProgramStart::Name, MB_ICONEXCLAMATION | MB_OK);
                exit(0);
            }
            if (Constants::breached)
            {
                MessageBoxA(NULL, "Possible malicious activity detected!", OnProgramStart::Name, MB_ICONEXCLAMATION | MB_OK);
                exit(0);
            }

            if (response.status_code == 200 || response.status_code == 201)
            {
                content = json::json::parse(response.text);
                User::ID = Utilities::removeQuotesFromString(to_string(content["id"]));
                User::Username = Utilities::removeQuotesFromString(to_string(content["username"]));
                User::Pasword = Utilities::removeQuotesFromString(to_string(content["password"]));
                User::Email = Utilities::removeQuotesFromString(to_string(content["email"]));
                User::Expiry = Utilities::removeQuotesFromString(to_string(content["expiryDate"]));
                User::LastLogin = Utilities::removeQuotesFromString(to_string(content["lastLogin"]));
                User::IP = Utilities::removeQuotesFromString(to_string(content["lastIP"]));
                User::HWID = Utilities::removeQuotesFromString(to_string(content["hwid"]));
                Security::End();
                return true;
            }
            else
            {
                content = json::json::parse(response.text);
                if (response.status_code == 0)
                {
                    MessageBoxA(NULL, "Unable to connect to the remote server!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
                    Security::End();
                    return false;
                }
                if (Utilities::removeQuotesFromString(to_string(content["code"])) == "NOT_FOUND")
                {
                    MessageBoxA(NULL, "License does not exist or already used!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
                }
                else if (Utilities::removeQuotesFromString(to_string(content["code"])) == "ER_DUP_ENTRY")
                {
                    MessageBoxA(NULL, "User with this username already exists!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
                }
                else if (Utilities::removeQuotesFromString(to_string(content["code"])) == "FORBIDDEN")
                {
                    MessageBoxA(NULL, "User with this username already exists!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
                }
                else if (Utilities::removeQuotesFromString(to_string(content["code"])) == "VALIDATION_FAILED")
                {
                    MessageBoxA(NULL, "Missing user register information!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
                }
                Security::End();
                return false;
            }
        }
        catch (const std::exception& ex)
        {
            MessageBoxA(NULL, "Unkown error, contact support!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
            std::cout << ex.what() << std::endl;
            Security::End();
            return false;
        }
    }

    static bool ExtendSub(std::string username, std::string password, std::string license)
    {
        if (!Constants::initialized)
        {
            MessageBoxA(NULL, "Please initialize your application first!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
            return false;
        }
        try
        {
            Security::Start();
            Constants::timeSent = time(NULL);
            json::json UserExtendDetails;
            UserExtendDetails["username"] = username;
            UserExtendDetails["password"] = password;
            UserExtendDetails["license"] = license;
            UserExtendDetails["hwid"] = HWID();
            auto response = cpr::Put(cpr::Url{ Constants::apiUrl + "users/upgrade" },
                cpr::Body{ UserExtendDetails.dump() },
                cpr::Header{ {"Content-Type", "application/json"} });
            json::json content;

            if (Security::MaliciousCheck(Constants::timeSent))
            {
                MessageBoxA(NULL, "Possible malicious activity detected!", OnProgramStart::Name, MB_ICONEXCLAMATION | MB_OK);
                exit(0);
            }
            if (Constants::breached)
            {
                MessageBoxA(NULL, "Possible malicious activity detected!", OnProgramStart::Name, MB_ICONEXCLAMATION | MB_OK);
                exit(0);
            }

            if (response.status_code == 200 || response.status_code == 201)
            {
                content = json::json::parse(response.text);
                User::ID = Utilities::removeQuotesFromString(to_string(content["id"]));
                User::Username = Utilities::removeQuotesFromString(to_string(content["username"]));
                User::Pasword = Utilities::removeQuotesFromString(to_string(content["password"]));
                User::Email = Utilities::removeQuotesFromString(to_string(content["email"]));
                User::Expiry = Utilities::removeQuotesFromString(to_string(content["expiryDate"]));
                User::LastLogin = Utilities::removeQuotesFromString(to_string(content["lastLogin"]));
                User::IP = Utilities::removeQuotesFromString(to_string(content["lastIP"]));
                User::HWID = Utilities::removeQuotesFromString(to_string(content["hwid"]));
                Security::End();
                return true;
            }
            else
            {
                content = json::json::parse(response.text);
                if (response.status_code == 0)
                {
                    MessageBoxA(NULL, "Unable to connect to the remote server!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
                    Security::End();
                    return false;
                }
                if (Utilities::removeQuotesFromString(to_string(content["code"])) == "NOT_FOUND")
                {
                    if (Utilities::removeQuotesFromString(to_string(content["message"])) == "The given username does not exist!")
                    {
                        MessageBoxA(NULL, "The given username does not exist!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
                    }
                    else if (Utilities::removeQuotesFromString(to_string(content["message"])) == "License does not exist or already used!")
                    {
                        MessageBoxA(NULL, "License does not exist or already used!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
                    }
                }
                else if (Utilities::removeQuotesFromString(to_string(content["code"])) == "UNAUTHORIZED")
                {
                    if (Utilities::removeQuotesFromString(to_string(content["message"])) == "The given username and password do not match!")
                    {
                        MessageBoxA(NULL, "The given username and password do not match!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
                    }
                    else if (Utilities::removeQuotesFromString(to_string(content["message"])) == "Your HWID does not match!")
                    {
                        MessageBoxA(NULL, "Your HWID does not match!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
                    }
                }
                else if (Utilities::removeQuotesFromString(to_string(content["code"])) == "VALIDATION_FAILED")
                {
                    MessageBoxA(NULL, "Missing user information!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
                }
                Security::End();
                return false;
            }
        }
        catch (const std::exception& ex)
        {
            MessageBoxA(NULL, "Unkown error, contact support!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
            std::cout << ex.what() << std::endl;
            Security::End();
            return false;
        }
    }
}