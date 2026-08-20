//
// kat //  11/8/22.
//

#include <binaryninjaapi.h>

using namespace BinaryNinja;

#include "KernelCacheTransforms.h"
#include "libDER/libDER.h"
#include "libimg4/img4.h"
#include "liblzfse/lzfse.h"
#include <algorithm>
#include <optional>

class IMG4PayloadTransform : public Transform
{

public:
    IMG4PayloadTransform(): Transform(DecodeTransform, TransformCapabilities(TransformSupportsDetection | TransformSupportsContext), "IMG4", "IMG4", "Container")
    {
    }

    // Attempt to decode a full IMG4 container first, falling back to decoding as a bare IM4P payload.
    // Returns the IM4P payload, which contains pointers into the input buffer.
    static std::optional<Img4Payload> DecodePayload(const uint8_t* data, size_t length)
    {
        DERSize derLen = static_cast<DERSize>(std::min(length, (size_t)std::numeric_limits<DERSize>::max()));

        DERItem der = {};
        der.data = (DERByte*)data;
        der.length = derLen;

        // Try unwrapping a full IMG4 container to get the inner IM4P item
        DERItem img4Items[4] = {};
        if (DERImg4Decode(&der, img4Items) == DR_Success)
            der = img4Items[1];

        // Parse the IM4P payload. We ignore DR_DecodeError as it is returned if the payload
        // has trailing fields, such as the optional "PAYP" (payload properties) item.
        Img4Payload payload = {};
        if (auto result = DERImg4DecodePayload(&der, &payload); result != DR_Success && result != DR_DecodeError)
            return std::nullopt;

        if (!payload.payload.data || !payload.payload.length)
            return std::nullopt;

        return payload;
    }

    virtual bool Decode(const DataBuffer& input, DataBuffer& output, const std::map<std::string, DataBuffer>& params) override
    {
        auto payload = DecodePayload((const uint8_t*)input.GetData(), input.GetLength());
        if (!payload)
            return false;

        output = DataBuffer(payload->payload.data, payload->payload.length);
        return true;
    }

    virtual bool DecodeWithContext(Ref<TransformContext> context, const std::map<std::string, DataBuffer>& params) override
    {
        if (!context || !context->GetInput())
            return false;

        const uint8_t* dataPtr = context->GetInput()->GetDataPointer();
        size_t dataLength = context->GetInput()->GetDataLength();
        if (!dataPtr || !dataLength)
            return false;

        auto payload = DecodePayload(dataPtr, dataLength);
        if (!payload)
            return false;

        // Synthesize name: <type>[.<version>]
        std::string filename = "";
        if (payload->type.data && payload->type.length)
            filename = std::string((const char*)payload->type.data, payload->type.length);
        if (payload->version.data && payload->version.length)
        {
            if (!filename.empty())
                filename += ".";
            filename += std::string((const char*)payload->version.data, payload->version.length);
        }

        if (payload->keybag.data && payload->keybag.length)
        {
           LogWarn("IMG4 payload contains keybag, which is not currently supported.");
        }

        context->SetChild(DataBuffer(payload->payload.data, payload->payload.length), filename, TransformSuccess, "", true);

        return true;
    }

    static void der_put_len(std::vector<uint8_t>& v, size_t len) {
        if (len < 0x80) { v.push_back(static_cast<uint8_t>(len)); return; }
        uint8_t tmp[9]; size_t n = 0;
        while (len) { tmp[n++] = static_cast<uint8_t>(len & 0xFF); len >>= 8; }
        v.push_back(static_cast<uint8_t>(0x80 | n));
        for (size_t i = 0; i < n; ++i) v.push_back(tmp[n - 1 - i]);
    }

    static void der_put_ia5(std::vector<uint8_t>& v, const void* s, size_t len) {
        v.push_back(0x16); // IA5String
        der_put_len(v, len);
        const uint8_t* p = static_cast<const uint8_t*>(s);
        v.insert(v.end(), p, p + len);
    }

    // TODO fix/support round-tripping. Encode always produces a bare IM4P, but Decode
    // accepts both bare IM4P and full IMG4 containers. Type/desc are also lost unless
    // passed via params.
    virtual bool Encode(const DataBuffer& input, DataBuffer& output, const std::map<std::string, DataBuffer>& params) override
    {
        // type (exactly 4 chars)
        const char* type = "krnl";
        if (auto it = params.find("type"); it != params.end()) {
            if (it->second.GetLength() != 4) return false;
            type = reinterpret_cast<const char*>(it->second.GetData());
        }
        // optional desc (IA5String)
        const char* desc = nullptr; size_t descLen = 0;
        if (auto it = params.find("desc"); it != params.end() && it->second.GetLength() > 0) {
            desc = reinterpret_cast<const char*>(it->second.GetData());
            descLen = it->second.GetLength();
        }

        // Build SEQUENCE content
        std::vector<uint8_t> body;
        der_put_ia5(body, "IM4P", 4);           // magic
        der_put_ia5(body, type, 4);             // type
        if (desc && descLen) der_put_ia5(body, desc, descLen); // optional

        // payload as [1] EXPLICIT OCTET STRING
        // std::vector<uint8_t> os;
        // os.push_back(0x04);                     // OCTET STRING
        // der_put_len(os, input.GetLength());
        // os.insert(os.end(),
        //           static_cast<const uint8_t*>(input.GetData()),
        //           static_cast<const uint8_t*>(input.GetData()) + input.GetLength());

        // body.push_back(0xA1);                   // [1] EXPLICIT
        // der_put_len(body, os.size());
        // body.insert(body.end(), os.begin(), os.end());

        // --- payload as *bare* OCTET STRING (what DERImg4DecodePayload expects) ---
        body.push_back(0x04);                                    // OCTET STRING
        der_put_len(body, input.GetLength());
        body.insert(body.end(),
                    static_cast<const uint8_t*>(input.GetData()),
                    static_cast<const uint8_t*>(input.GetData()) + input.GetLength());


        // Wrap in SEQUENCE
        std::vector<uint8_t> out;
        out.push_back(0x30);                    // SEQUENCE
        der_put_len(out, body.size());
        out.insert(out.end(), body.begin(), body.end());

        output = DataBuffer(out.data(), out.size()); // copies
        return true;
    }

    virtual bool CanDecode(Ref<BinaryView> input) const override
    {
        uint8_t header[64];
        size_t bytesRead = input->Read(header, 0, sizeof(header));
        if (bytesRead < sizeof(header))
            return false;

        const uint8_t* data = header;
        size_t headerLength = bytesRead;
        size_t inputLength = input->GetLength();

        auto parseDerLen = [](const uint8_t* ptr, size_t available) -> std::pair<size_t, size_t> {
            if (!available)
                return {0, 0};

            uint8_t firstByte = ptr[0];
            if (firstByte < 0x80) // Short form
                return {firstByte, 1};
            if (firstByte == 0x80) // Invalid indefinite length
                return {0, 0};

            size_t lengthBytes = firstByte & 0x7F;
            if (lengthBytes == 0 || lengthBytes > sizeof(size_t) || lengthBytes >= available || ptr[1] == 0x00)
                return {0, 0};

            size_t result = 0;
            for (size_t i = 0; i < lengthBytes; ++i)
                result = (result << 8) | ptr[1 + i];
            return {result, 1 + lengthBytes};
        };

        if (headerLength < 8) // Minimum: SEQUENCE tag(1) + len(1) + IA5String tag(1) + len(1) + "IM4P"(4)
            return false;

        if (data[0] != 0x30) // Check for DER sequence start
            return false;

        auto [seqLen, seqLenHdr] = parseDerLen(data + 1, headerLength - 1);
        if (!seqLen || !seqLenHdr || ((seqLen + 1 + seqLenHdr) > inputLength))
            return false;

        size_t offset = 1 + seqLenHdr;
        size_t seqEnd = offset + seqLen;

        if (seqLen > (inputLength - offset))
            return false;

        // parse up to the first 5 elements to find the magic "IM4P" or "IMG4"
        for (int i = 0; i < 5 && offset < seqEnd; ++i)
        {
            if (offset >= headerLength)
                return false;

            if (seqEnd - offset < 2)
                return false;
            uint8_t tag = data[offset++];
            if (offset >= headerLength)
                return false;

            auto [elementLen, elementLenHdr] = parseDerLen(data + offset, std::min(seqEnd - offset, headerLength - offset));
            if (!elementLen || !elementLenHdr || (elementLen > (seqEnd - offset - elementLenHdr)))
                return false;
            offset += elementLenHdr;
            if (offset + elementLen > headerLength)
                return false;
            if (tag == 0x16 && elementLen == 4 && (memcmp(data + offset, "IM4P", 4) == 0 || memcmp(data + offset, "IMG4", 4) == 0))
                return true;
            offset += elementLen;
        }

        return false;
    }
};

class LZFSETransform : public Transform
{

public:
    LZFSETransform(): Transform(BinaryCodecTransform, TransformSupportsDetection, "LZFSE", "LZFSE", "Compress")
    {
    }

    virtual bool Decode(const DataBuffer& input, DataBuffer& output, const std::map<std::string, DataBuffer>& params) override
    {
        size_t outputBufferSize = input.GetLength() * 6;
        std::unique_ptr<uint8_t[]> scratchBuffer(new uint8_t[lzfse_decode_scratch_size()]);
        while (true)
        {
            output.SetSize(outputBufferSize);
            size_t outSize = lzfse_decode_buffer((uint8_t *)output.GetData(), outputBufferSize, (uint8_t *)input.GetData(), input.GetLength(), scratchBuffer.get());
            if (!outSize)
                return false;
            if ((outSize > 0) && (outSize < outputBufferSize))
            {
                output.SetSize(outSize);
                return true;
            }
            if (output.GetLength() > (size_t(1) << 33)) // 8GB max
                return false;
            outputBufferSize *= 2;
        }

        return false;
    }


    virtual bool DecodeWithContext(Ref<TransformContext> context, const std::map<std::string, DataBuffer>& params) override
    {
        if (!context || !context->GetInput())
            return false;

        const uint8_t* dataPtr = context->GetInput()->GetDataPointer();
        size_t dataLength = context->GetInput()->GetDataLength();
        if (!dataPtr || !dataLength)
            return false;

        size_t outputBufferSize = dataLength * 6;
        std::unique_ptr<uint8_t[]> scratchBuffer(new uint8_t[lzfse_decode_scratch_size()]);
        while (true)
        {
            DataBuffer output(outputBufferSize);
            size_t outSize = lzfse_decode_buffer((uint8_t *)output.GetData(), outputBufferSize, (uint8_t *)dataPtr, dataLength, scratchBuffer.get());
            if (!outSize)
                return false;
            if ((outSize > 0) && (outSize < outputBufferSize))
            {
                output.SetSize(outSize);
                context->SetChild(output, "");
                return true;
            }
            if (output.GetLength() > (size_t(1) << 33)) // 8GB max
                return false;
            outputBufferSize *= 2;
        }

        return false;
    }


    virtual bool Encode(const DataBuffer& input, DataBuffer& output, const std::map<std::string, DataBuffer>&) override
    {
        size_t outputBufferSize = input.GetLength() + (input.GetLength() / 16) + 64;
        std::unique_ptr<uint8_t[]> scratchBuffer(new uint8_t[lzfse_encode_scratch_size()]);
        for (int attempts = 0; attempts < 10; attempts++)
        {
            output.SetSize(outputBufferSize);
            size_t outSize = lzfse_encode_buffer((uint8_t *)output.GetData(), outputBufferSize, (uint8_t *)input.GetData(), input.GetLength(), scratchBuffer.get());
            if (outSize > 0)
            {
                output.SetSize(outSize);
                return true;
            }
            outputBufferSize *= 2;
        }

        return false;
    }

    virtual bool CanDecode(Ref<BinaryView> input) const override
    {
        uint8_t header[4];
        if (input->Read(header, 0, 4) < 4)
            return false;

        if (header[0] != 0x62 || header[1] != 0x76 || header[2] != 0x78) // Check for "bvx" prefix (common to all LZFSE blocks)
            return false;

        switch (header[3])
        {
            case '-': // raw
            case '1': // compressed v1
            case '2': // compressed v2
            case 'n': // LZVN
                return true;
            default:
                return false;
        }
    }
};


void RegisterTransformers() {
    Transform::Register(new IMG4PayloadTransform());
    Transform::Register(new LZFSETransform());
}