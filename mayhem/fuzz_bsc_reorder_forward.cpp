#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>
#include "libbsc.h"

extern "C" int bsc_reorder_forward(unsigned char *T, int n, int recordSize, int features);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 200)
    {
        return 0;
    }

    FuzzedDataProvider provider(data, size);
    int features = provider.ConsumeIntegral<int>();
    int recordSize = provider.ConsumeIntegralInRange<int>(-1, 10);

    bsc_init(features);
    std::vector<unsigned char> vec = provider.ConsumeBytes<unsigned char>(100);

    bsc_reorder_forward(&vec[0], 100, recordSize, features);

    return 0;
}
