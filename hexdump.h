#pragma once
#include <stdio.h>
void hex_dump(
    const char *desc,
    const void *addr,
    const int len,
    int perLine,
    size_t offset);