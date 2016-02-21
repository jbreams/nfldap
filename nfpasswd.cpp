#include <termios.h>
#include <unistd.h>

#include <iostream>

#include "passwords.h"

std::string readPassword(const char* prompt) {
    std::cout << prompt;
    struct termios ttyNew, ttyOld;
    tcgetattr(STDIN_FILENO, &ttyOld);

    ttyNew = ttyOld;
    ttyNew.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &ttyNew);

    std::string password;
    std::getline(std::cin, password);

    tcsetattr(STDIN_FILENO, TCSAFLUSH, &ttyOld);
    std::cout << std::endl;

    return password;
}

int main() {
    Password::init();
    auto password = readPassword("Enter password: ");
    auto passwordCheck = readPassword("Re-enter password: ");
    if (password != passwordCheck) {
        std::cout << "Passwords do not match!" << std::endl;
        exit(1);
    }

    std::cout << Password::generatePassword(password) << std::endl;
    return 0;
}
