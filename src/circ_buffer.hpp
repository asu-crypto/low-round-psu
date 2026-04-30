#pragma once

#include "cryptoTools/Common/Aligned.h"

namespace circ_buff {

    struct buff {
        osuCrypto::AlignedUnVector<__int128> data;
    };

}