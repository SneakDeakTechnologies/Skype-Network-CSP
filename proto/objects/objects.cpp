// proto/objects/objects.cpp

bool read_skype_varint(const unsigned char** buffer, const unsigned char* buffer_end, int* value) {
    if (*buffer >= buffer_end) return false;
    *value = 0;
    int shift = 0;
    while (*buffer < buffer_end) {
        unsigned char b = **buffer;
        (*buffer)++;
        *value |= (b & 0x7F) << shift;
        if (!(b & 0x80)) return true;
        shift += 7;
        if (shift >= 32) break;
    }
    return false;
}

int write_skype_varint(unsigned char* buffer, unsigned int value)
{
    int n = 0;
    while (value > 0x7F)
    {
        buffer[n++] = (unsigned char)((value & 0x7F) | 0x80);
        value >>= 7;
    }
    buffer[n++] = (unsigned char)(value & 0x7F);
    return n;
}
