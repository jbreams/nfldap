#include <string>

namespace Password {

bool checkPassword(std::string password, std::string rawHashedPassword);
std::string generatePassword(std::string password);
void init();

} // namespace password

