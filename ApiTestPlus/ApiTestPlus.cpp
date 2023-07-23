#include <iostream>
#include <cpr/cpr.h>
#include "api.h"

int main()
{   
    API::OnProgramStart::Initialize("APP NAME", "APP SECRET", "APP VERSION");

    std::string option, username, password, email, twoFactorCode;
    std::string license = "N/A";

    std::cout << "\n[1] Login" << std::endl;
    std::cout << "[2] Register" << std::endl;
    if (!API::ApplicationSettings::freeMode)
        std::cout << "[3] Extend Subscription" << std::endl;
    std::cout << "\nOption:" << std::endl;
    std::cin >> option;

    if (option == "1")
    {
        system("CLS");
        std::cout << "\nUsername: ";
        std::cin >> username;
        std::cout << "\nPassword: ";
        std::cin >> password;
        std::cout << "\n2FA code (if enabled): ";
        std::cin >> twoFactorCode;
        if (API::Login(username, password, twoFactorCode))
        {
            MessageBoxA(NULL, "Successfully Logged In!", API::OnProgramStart::Name, MB_ICONINFORMATION | MB_OK);
            API::Log(API::User::Username, "User logged in");
            system("CLS");
            std::cout << "\nID: " + API::User::ID << std::endl;
            std::cout << "Username: " + API::User::Username << std::endl;
            std::cout << "Email: " + API::User::Email << std::endl;
            std::cout << "Subscription Expiry: " + API::User::Expiry << std::endl;
            std::cout << "HWID: " + API::User::HWID << std::endl;
            std::cout << "Last Login: " + API::User::LastLogin << std::endl;
            std::cout << "IP: " + API::User::IP << std::endl;
            //do code that you want
            std::cout << "\nPress 1 to enable 2FA, press 2 to disable 2FA:";
            std::cin >> option;
            if (option == "1")
            {
                API::CreateQRCode();
                std::cout << "QR Code:";
                std::cin >> twoFactorCode;
                API::Verify2FA(twoFactorCode);
                system("pause");
            }
            else if (option == "2")
            {
                std::cout << "QR Code:";
                std::cin >> twoFactorCode;
                API::Disable2FA(twoFactorCode);
                system("pause");
            }
        }
        else
        {
            exit(0);
        }
    }
    else if (option == "2")
    {
        system("CLS");
        std::cout << "\nUsername: ";
        std::cin >> username;
        std::cout << "\nPassword: ";
        std::cin >> password;
        std::cout << "\nEmail: ";
        std::cin >> email;
        if (!API::ApplicationSettings::freeMode)
        {
            std::cout << "\nLicense: ";
            std::cin >> license;
        }

        if (API::Register(username, password, email, license))
        {
            MessageBoxA(NULL, "Successfully Registered!", API::OnProgramStart::Name, MB_ICONINFORMATION | MB_OK);
            API::Log(API::User::Username, "User registered");
            system("pause");
            //do code that you want
        }
        else
        {
            exit(0);
        }
    }
    if (!API::ApplicationSettings::freeMode)
    {
        if (option == "3")
        {
            system("CLS");
            std::cout << "\nUsername: ";
            std::cin >> username;
            std::cout << "\nPassword: ";
            std::cin >> password;
            std::cout << "\nLicense: ";
            std::cin >> license;
            if (API::ExtendSub(username, password, license))
            {
                MessageBoxA(NULL, "Successfully Extended Your Subscription!", API::OnProgramStart::Name, MB_ICONINFORMATION | MB_OK);
                API::Log(API::User::Username, "User extended");
                system("pause");
                //do code that you want
            }
            else
            {
                exit(0);
            }
        }
    }
}
