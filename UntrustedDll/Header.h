#pragma once

extern "C" __declspec(dllexport) void accessPersonalData(
        char* outbuf,
        const size_t len,
        const size_t i);