#ifndef INPUTCLASS_H
#define INPUTCLASS_H

#include <string>

class InputClass {
public:
    InputClass();
    explicit InputClass(std::string initialInput); // Mark constructor explicit
    ~InputClass();

    void setInput(std::string new_input); // Update signature
    std::string getInput() const;

private:
    std::string input;
};

#endif //INPUTCLASS_H