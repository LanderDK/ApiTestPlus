#include <iostream>
#include <cpr/cpr.h>
#include "api.h"

int main()
{
    API::OnProgramStart::Initialize("BlitzWare", "b15d1b577a28d6db8526a7b7e4cb9c566b9c7957c9831660eac405ddc3d382a4", "1.0");

    std::string option, username, password, email, license;

    std::cout << "\n[1] Login" << std::endl;
    std::cout << "[2] Register" << std::endl;
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
        if (API::Login(username, password))
        {
            MessageBox(NULL, L"Successfully Logged In!", API::OnProgramStart::Name, MB_ICONINFORMATION | MB_OK);
            system("CLS");
            std::cout << "\nID: " + API::User::ID << std::endl;
            std::cout << "Username: " + API::User::Username << std::endl;
            std::cout << "Email: " + API::User::Email << std::endl;
            std::cout << "Subscription Expiry: " + API::User::Expiry << std::endl;
            std::cout << "HWID: " + API::User::HWID << std::endl;
            std::cout << "Last Login: " + API::User::LastLogin << std::endl;
            std::cout << "IP: " + API::User::IP << std::endl;
            //do code that you want
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
        std::cout << "\nLicense: ";
        std::cin >> license;
        if (API::Register(username, password, email, license))
        {
            MessageBox(NULL, L"Successfully Registered!", API::OnProgramStart::Name, MB_ICONINFORMATION | MB_OK);
            //do code that you want
        }
        else
        {
            exit(0);
        }
    }
    else if (option == "3")
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
            MessageBox(NULL, L"Successfully Extended Your Subscription!", API::OnProgramStart::Name, MB_ICONINFORMATION | MB_OK);
            //do code that you want
        }
        else
        {
            exit(0);
        }
    }
}