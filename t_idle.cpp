#include "fetchmail.h"
#include <iostream>

const char *program_name;

int main()
{
    program_name = "t_idle";

    for (;;) {
        std::cout << "How may I serve you, master?\n";
        interruptible_idle(5);
    }
}
