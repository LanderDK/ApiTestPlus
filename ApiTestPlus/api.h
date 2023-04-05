#pragma once
#include <string>
#include "utils.h"
#include <cpr/api.h>
#include <nlohmann/json.hpp>
#include <typeinfo>
#include <iostream>
#include <chrono>
#include <ctime>
#include "md5.h"
namespace json = nlohmann;
#define MSGBOX(x) \
{ \
   std::ostringstream oss; \
   oss << x; \
   MessageBox(oss.str().c_str(), "Msg Title", MB_OK | MB_ICONQUESTION); \
}

namespace API
{
    namespace Constants
    {
        std::string apiUrl = "https://api.blitzware.xyz/api/";
        bool initialized = false;
        bool started = false;
        bool breached = false;
        auto timeSent = std::chrono::system_clock::now();
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

    namespace Security
    {
        static void Start()
        {
            if (API::Constants::started)
            {
                MessageBox(NULL, L"A session has already been started, please end the previous one!", L"ERROR", MB_ICONERROR | MB_OK);
                exit(0);
            }
            else
            {
                API::Constants::started = true;
            }
        }

        static void End()
        {
            if (!API::Constants::started)
            {
                MessageBox(NULL, L"No session has been started, closing for security reasons!", L"ERROR", MB_ICONERROR | MB_OK);
                exit(0);
            }
            else
            {
                API::Constants::started = false;
            }
        }

        static std::string Integrity(std::string filename)
        {
            std::string result = md5(filename);
            return result;
        }

        static bool MaliciousCheck(std::chrono::system_clock::time_point date)
        {
            auto start = date; //time sent
            auto end = std::chrono::system_clock::now(); //time recieved
            std::chrono::duration<double> elapsed_seconds = end - start;
            typedef std::chrono::duration<float> float_seconds;
            auto secs = std::chrono::duration_cast<float_seconds>(elapsed_seconds);
            if (elapsed_seconds.count() >= 5.0)
            {
                Constants::breached = true;
                return true;
            }
            else
            {
                return false;
            }
        }
    }

    namespace OnProgramStart
    {
        LPCWSTR Name;

        void Initialize(std::string name, std::string secret, std::string version)
        {
            std::wstring nameNotConverted = std::wstring(name.begin(), name.end());
            Name = nameNotConverted.c_str();
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
                    MessageBox(NULL, L"Possible malicious activity detected!", OnProgramStart::Name, MB_ICONEXCLAMATION | MB_OK);
                    exit(0);
                }
                if (Constants::breached)
                {
                    MessageBox(NULL, L"Possible malicious activity detected!", OnProgramStart::Name, MB_ICONEXCLAMATION | MB_OK);
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
                        MessageBox(NULL, L"Application is in Free Mode!", OnProgramStart::Name,
                            MB_ICONINFORMATION | MB_OK);

                    if (ApplicationSettings::developerMode)
                    {
                        MessageBox(NULL, L"Application is in Developer Mode, bypassing integrity and update check!", OnProgramStart::Name,
                            MB_ICONEXCLAMATION | MB_OK);
                        std::ofstream outfile("integrity.txt");
                        outfile << Security::Integrity(Utilities::GetExeFileName()) << std::endl;
                        outfile.close();
                        MessageBox(NULL, L"Your applications hash has been saved to integrity.txt, please refer to this when your application is ready for release!",
                            OnProgramStart::Name, MB_ICONINFORMATION | MB_OK);
                    }
                    else
                    {
                        if (ApplicationSettings::version != version)
                        {
                            MessageBox(NULL, L"Update is available, redirecting to update!", OnProgramStart::Name,
                                MB_ICONERROR | MB_OK);
                            system(std::string("start " + ApplicationSettings::downloadLink).c_str());
                            exit(0);
                        }
                        if (ApplicationSettings::integrityCheck)
                        {
                            if (ApplicationSettings::programHash != Security::Integrity(Utilities::GetExeFileName()))
                            {
                                MessageBox(NULL, L"File has been tampered with, couldn't verify integrity!", OnProgramStart::Name,
                                    MB_ICONERROR | MB_OK);
                                exit(0);
                            }
                        }
                    }
                    if (ApplicationSettings::status == false)
                    {
                        MessageBox(NULL, L"Looks like this application is disabled, please try again later!", OnProgramStart::Name,
                            MB_ICONERROR | MB_OK);
                        exit(0);
                    }
                }
                else
                {
                    content = json::json::parse(response.text);
                    if (response.status_code == 0)
                    {
                        MessageBox(NULL, L"Unable to connect to the remote server!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
                        exit(0);
                    }
                    if (Utilities::removeQuotesFromString(to_string(content["code"])) == "NOT_FOUND")
                    {
                        MessageBox(NULL, L"Application does not exist!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
                        exit(0);
                    }
                    else if (Utilities::removeQuotesFromString(to_string(content["code"])) == "VALIDATION_FAILED")
                    {
                        MessageBox(NULL, L"Failed to initialize your application correctly!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
                        exit(0);
                    }
                }
                Security::End();
            }
            catch (const std::exception& ex)
            {
                MessageBox(NULL, L"Unkown error, contact support!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
                std::cout << ex.what() << std::endl;
            }
        }
    };

    static bool Login(std::string username, std::string password)
    {
        if (!Constants::initialized)
        {
            MessageBox(NULL, L"Please initialize your application first!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
            return false;
        }
        try
        {
            Security::Start();
            Constants::timeSent = std::chrono::system_clock::now();
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
                MessageBox(NULL, L"Possible malicious activity detected!", OnProgramStart::Name, MB_ICONEXCLAMATION | MB_OK);
                exit(0);
            }
            if (Constants::breached)
            {
                MessageBox(NULL, L"Possible malicious activity detected!", OnProgramStart::Name, MB_ICONEXCLAMATION | MB_OK);
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
                    MessageBox(NULL, L"Unable to connect to the remote server!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
                    Security::End();
                    return false;
                }
                if (Utilities::removeQuotesFromString(to_string(content["code"])) == "NOT_FOUND")
                {
                    MessageBox(NULL, L"The given username does not exist!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
                }
                else if (Utilities::removeQuotesFromString(to_string(content["code"])) == "VALIDATION_FAILED")
                {
                    MessageBox(NULL, L"Missing user login information!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
                }
                else if (Utilities::removeQuotesFromString(to_string(content["code"])) == "UNAUTHORIZED")
                {
                    if (Utilities::removeQuotesFromString(to_string(content["message"])) == "The given username and password do not match!")
                    {
                        MessageBox(NULL, L"The given username and password do not match!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
                    }
                    else if (Utilities::removeQuotesFromString(to_string(content["message"])) == "Your subscription has expired!")
                    {
                        MessageBox(NULL, L"Your subscription has expired!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
                    }
                    else if (Utilities::removeQuotesFromString(to_string(content["message"])) == "Your HWID does not match!")
                    {
                        MessageBox(NULL, L"Your HWID does not match!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
                    }
                }
                Security::End();
                return false;
            }
        }
        catch (const std::exception& ex)
        {
            MessageBox(NULL, L"Unkown error, contact support!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
            std::cout << ex.what() << std::endl;
            Security::End();
            return false;
        }
    }

    static bool Register(std::string username, std::string password, std::string email, std::string license)
    {
        if (!Constants::initialized)
        {
            MessageBox(NULL, L"Please initialize your application first!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
            return false;
        }
        try
        {
            Security::Start();
            Constants::timeSent = std::chrono::system_clock::now();
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
                MessageBox(NULL, L"Possible malicious activity detected!", OnProgramStart::Name, MB_ICONEXCLAMATION | MB_OK);
                exit(0);
            }
            if (Constants::breached)
            {
                MessageBox(NULL, L"Possible malicious activity detected!", OnProgramStart::Name, MB_ICONEXCLAMATION | MB_OK);
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
                    MessageBox(NULL, L"Unable to connect to the remote server!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
                    Security::End();
                    return false;
                }
                if (Utilities::removeQuotesFromString(to_string(content["code"])) == "NOT_FOUND")
                {
                    MessageBox(NULL, L"License does not exist or already used!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
                }
                else if (Utilities::removeQuotesFromString(to_string(content["code"])) == "ER_DUP_ENTRY")
                {
                    MessageBox(NULL, L"User with this username already exists!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
                }
                else if (Utilities::removeQuotesFromString(to_string(content["code"])) == "FORBIDDEN")
                {
                    MessageBox(NULL, L"User with this username already exists!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
                }
                else if (Utilities::removeQuotesFromString(to_string(content["code"])) == "VALIDATION_FAILED")
                {
                    MessageBox(NULL, L"Missing user register information!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
                }
                Security::End();
                return false;
            }
        }
        catch (const std::exception& ex)
        {
            MessageBox(NULL, L"Unkown error, contact support!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
            std::cout << ex.what() << std::endl;
            Security::End();
            return false;
        }
    }

    static bool ExtendSub(std::string username, std::string password, std::string license)
    {
        if (!Constants::initialized)
        {
            MessageBox(NULL, L"Please initialize your application first!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
            return false;
        }
        try
        {
            Security::Start();
            Constants::timeSent = std::chrono::system_clock::now();
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
                MessageBox(NULL, L"Possible malicious activity detected!", OnProgramStart::Name, MB_ICONEXCLAMATION | MB_OK);
                exit(0);
            }
            if (Constants::breached)
            {
                MessageBox(NULL, L"Possible malicious activity detected!", OnProgramStart::Name, MB_ICONEXCLAMATION | MB_OK);
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
                    MessageBox(NULL, L"Unable to connect to the remote server!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
                    Security::End();
                    return false;
                }
                if (Utilities::removeQuotesFromString(to_string(content["code"])) == "NOT_FOUND")
                {
                    if (Utilities::removeQuotesFromString(to_string(content["message"])) == "The given username does not exist!")
                    {
                        MessageBox(NULL, L"The given username does not exist!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
                    }
                    else if (Utilities::removeQuotesFromString(to_string(content["message"])) == "License does not exist or already used!")
                    {
                        MessageBox(NULL, L"License does not exist or already used!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
                    }
                }
                else if (Utilities::removeQuotesFromString(to_string(content["code"])) == "UNAUTHORIZED")
                {
                    if (Utilities::removeQuotesFromString(to_string(content["message"])) == "The given username and password do not match!")
                    {
                        MessageBox(NULL, L"The given username and password do not match!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
                    }
                    else if (Utilities::removeQuotesFromString(to_string(content["message"])) == "Your HWID does not match!")
                    {
                        MessageBox(NULL, L"Your HWID does not match!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
                    }
                }
                else if (Utilities::removeQuotesFromString(to_string(content["code"])) == "VALIDATION_FAILED")
                {
                    MessageBox(NULL, L"Missing user information!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
                }
                Security::End();
                return false;
            }
        }
        catch (const std::exception& ex)
        {
            MessageBox(NULL, L"Unkown error, contact support!", OnProgramStart::Name, MB_ICONERROR | MB_OK);
            std::cout << ex.what() << std::endl;
            Security::End();
            return false;
        }
    }
}