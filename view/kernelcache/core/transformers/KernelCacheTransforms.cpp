//
// kat //  11/8/22.
//

#include <binaryninjaapi.h>

using namespace BinaryNinja;

#include "KernelCacheTransforms.h"
#include "libDER/libDER.h"
#include "libimg4/img4.h"
#include "liblzfse/lzfse.h"

class IMG4PayloadTransform : public Transform
{

public:
    IMG4PayloadTransform():
            Transform(DecodeTransform, "IMG4-Unencrypted", "IMG4-Unencrypted", "IMG4")
    {
    }

    virtual bool Decode(const DataBuffer& input, DataBuffer& output, const std::map<std::string, DataBuffer>& params)
    {
        DERItem* item = new DERItem;
        item->data = (DERByte *)input.GetData();
        item->length = input.GetLength();

        Img4Payload *payload = new Img4Payload;
        DERImg4DecodePayload(item, payload);

        output = DataBuffer(payload->payload.data, payload->payload.length);

        return true;
    }
};

class LZFSETransform : public Transform
{

public:
    LZFSETransform(): Transform(BinaryCodecTransform, "LZFSE", "LZFSE", "Compress")
    {
    }

    virtual bool Decode(const DataBuffer& input, DataBuffer& output, const std::map<std::string, DataBuffer>& params)
    {
        size_t outputBufferSize = input.GetLength() * 6;
        std::unique_ptr<uint8_t[]> lzfseOutputBuffer(new uint8_t[outputBufferSize]);
        std::unique_ptr<uint8_t[]> scratchBuffer(new uint8_t[lzfse_decode_scratch_size()]);
        size_t outSize = lzfse_decode_buffer(lzfseOutputBuffer.get(), outputBufferSize,
                                            (uint8_t *)input.GetData(), input.GetLength(),
                                            scratchBuffer.get());
        if (!outSize)
            return false;
        output = DataBuffer(lzfseOutputBuffer.get(), outSize);
        return true;
    }

    virtual bool Encode(const DataBuffer& input, DataBuffer& output, const std::map<std::string, DataBuffer>&)
    {
        size_t outputBufferSize = input.GetLength() + (input.GetLength() / 16) + 64;
        std::unique_ptr<uint8_t[]> lzfseOutputBuffer(new uint8_t[outputBufferSize]);
        std::unique_ptr<uint8_t[]> scratchBuffer(new uint8_t[lzfse_encode_scratch_size()]);
        size_t outSize = lzfse_encode_buffer(lzfseOutputBuffer.get(), outputBufferSize,
                                            (uint8_t *)input.GetData(), input.GetLength(),
                                            scratchBuffer.get());
        if (!outSize)
            return false;
        output = DataBuffer(lzfseOutputBuffer.get(), outSize);
        return true;
    }
};


void RegisterTransformers() {
    Transform::Register(new IMG4PayloadTransform());
    Transform::Register(new LZFSETransform());
}