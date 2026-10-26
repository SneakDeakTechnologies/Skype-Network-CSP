// proto/pack-4142/ext42.h
#pragma once

#include "../../proto/common/skype_basics.h"

#ifdef __cplusplus
extern "C" {
#endif

	int main_unpack(u8* indata, u32 inlen);
	int main_unpack_saveip(u8* indata, u32 inlen);
	int main_pack(skype_thing* mythings, int mythings_len, u8* outdata, u32 maxlen);
    int main_unpack_get_binary(
        u8* indata,
        u32 inlen,
        u32 wanted_type,
        u32 wanted_id,
        u8* outdata,
        u32 out_capacity,
        u32* out_size
    );

#ifdef __cplusplus
}
#endif
