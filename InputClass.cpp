//
// Created by HomePC on 5/22/2025.
//

#include "InputClass.h"
#include <iostream>
#include <utility> // Required for std::move

InputClass::InputClass() = default;

// Parameter 'initialInput' is taken by value.
// The std::move in the initializer list is appropriate for this.
InputClass::InputClass(std::string initialInput): input(std::move(initialInput)) {
    // Corrected log message to reflect that initialInput is passed by value.
    std::cout << "InputClass(std::string initialInput) [moved from initialInput]" << std::endl;
}

// Changed to take 'new_input' by value to optimize for both lvalues and rvalues.
// If an lvalue is passed, 'new_input' is a copy.
// If an rvalue is passed, 'new_input' can be move-constructed (if the compiler can).
// Then we move from 'new_input' into 'this->input'.
void InputClass::setInput(std::string new_input) {
    this->input = std::move(new_input);
}

std::string InputClass::getInput() const {
    return input;
}

InputClass::~InputClass() = default;