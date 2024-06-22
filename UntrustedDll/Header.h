#pragma once

extern "C" __declspec(dllexport) void accessPersonalData(
        char* outbuf,
        const size_t len,
        const size_t i);

extern "C" __declspec(dllexport) void setPersonalData(
    char* inbuf,
    const size_t len,
    const size_t i);