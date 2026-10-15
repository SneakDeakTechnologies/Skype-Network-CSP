// proto/objects/objects.h
#pragma once

bool read_skype_varint(const unsigned char** buffer, const unsigned char* buffer_end, int* value);
int write_skype_varint(unsigned char* buffer, unsigned int value);
