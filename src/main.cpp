#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdint>
#include <iomanip>
#include <filesystem>
#include <algorithm>

#include "../third_party/tinyxml2.h"

extern "C" {
#define AES128 1
#include "../third_party/aes.h"
#include "../third_party/md5.h"
}

namespace fs = std::filesystem;

// Helpers
std::vector<uint8_t> hex2bin(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t) strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

std::string bin2hex(const uint8_t* data, size_t len) {
    std::string hex;
    const char* hex_chars = "0123456789abcdef";
    for (size_t i = 0; i < len; ++i) {
        hex += hex_chars[(data[i] >> 4) & 0xF];
        hex += hex_chars[data[i] & 0xF];
    }
    return hex;
}

void aes_cfb_decrypt(uint8_t* data, size_t length, const uint8_t* key, const uint8_t* iv) {
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, key);
    
    uint8_t previous_ciphertext[16];
    memcpy(previous_ciphertext, iv, 16);
    
    for (size_t i = 0; i < length; i += 16) {
        uint8_t encrypted_iv[16];
        memcpy(encrypted_iv, previous_ciphertext, 16);
        
        AES_ECB_encrypt(&ctx, encrypted_iv);
        
        size_t block_size = (length - i) > 16 ? 16 : (length - i);
        
        uint8_t current_ciphertext[16];
        memcpy(current_ciphertext, data + i, block_size);
        
        for (size_t j = 0; j < block_size; ++j) {
            data[i + j] ^= encrypted_iv[j];
        }
        
        memcpy(previous_ciphertext, current_ciphertext, 16);
    }
}

void md5(const uint8_t* data, size_t len, uint8_t* result) {
    MD5Context ctx;
    md5Init(&ctx);
    md5Update(&ctx, (uint8_t*)data, len);
    md5Finalize(&ctx);
    memcpy(result, ctx.digest, 16);
}

// ----------------------------------------------------------------------
// MTK Logic
// ----------------------------------------------------------------------

void mtk_shuffle(const uint8_t* key, size_t keylength, uint8_t* input, size_t inputlength) {
    for (size_t i = 0; i < inputlength; i++) {
        uint8_t k = key[i % keylength];
        uint8_t h = ((input[i] & 0xF0) >> 4) | (16 * (input[i] & 0xF));
        input[i] = k ^ h;
    }
}

void mtk_shuffle2(const uint8_t* key, size_t keylength, uint8_t* input, size_t inputlength) {
    for (size_t i = 0; i < inputlength; i++) {
        uint8_t tmp = key[i % keylength] ^ input[i];
        input[i] = ((tmp & 0xF0) >> 4) | (16 * (tmp & 0xF));
    }
}

const std::vector<std::vector<std::string>> mtk_keytables = {
    {"67657963787565E837D226B69A495D21", "F6C50203515A2CE7D8C3E1F938B7E94C", "42F2D5399137E2B2813CD8ECDF2F4D72"},
    {"9E4F32639D21357D37D226B69A495D21", "A3D8D358E42F5A9E931DD3917D9A3218", "386935399137416B67416BECF22F519A"},
    {"892D57E92A4D8A975E3C216B7C9DE189", "D26DF2D9913785B145D18C7219B89F26", "516989E4A1BFC78B365C6BC57D944391"},
    {"27827963787265EF89D126B69A495A21", "82C50203285A2CE7D8C3E198383CE94C", "422DD5399181E223813CD8ECDF2E4D72"},
    {"3C4A618D9BF2E4279DC758CD535147C3", "87B13D29709AC1BF2382276C4E8DF232", "59B7A8E967265E9BCABE2469FE4A915E"},
    {"1C3288822BF824259DC852C1733127D3", "E7918D22799181CF2312176C9E2DF298", "3247F889A7B6DECBCA3E28693E4AAAFE"},
    {"1E4F32239D65A57D37D2266D9A775D43", "A332D3C3E42F5A3E931DD991729A321D", "3F2A35399A373377674155ECF28FD19A"},
    {"122D57E92A518AFF5E3C786B7C34E189", "DD6DF2D9543785674522717219989FB0", "12698965A132C76136CC88C5DD94EE91"},
    {"ab3f76d7989207f2", "2bf515b3a9737835"}
};

void mtk_getkey(size_t index, std::vector<uint8_t>& aeskey, std::vector<uint8_t>& aesiv) {
    if (mtk_keytables[index].size() == 3) {
        std::vector<uint8_t> obskey = hex2bin(mtk_keytables[index][0]);
        std::vector<uint8_t> encaeskey = hex2bin(mtk_keytables[index][1]);
        std::vector<uint8_t> encaesiv = hex2bin(mtk_keytables[index][2]);
        
        mtk_shuffle2(obskey.data(), 16, encaeskey.data(), 16);
        uint8_t md5_hash1[16];
        md5((uint8_t*)encaeskey.data(), 16, md5_hash1);
        std::string hex_hash1 = bin2hex(md5_hash1, 16);
        aeskey = hex2bin(hex_hash1);
        
        mtk_shuffle2(obskey.data(), 16, encaesiv.data(), 16);
        uint8_t md5_hash2[16];
        md5((uint8_t*)encaesiv.data(), 16, md5_hash2);
        std::string hex_hash2 = bin2hex(md5_hash2, 16);
        aesiv = hex2bin(hex_hash2);
    } else {
        aeskey = std::vector<uint8_t>(mtk_keytables[index][0].begin(), mtk_keytables[index][0].end());
        aesiv = std::vector<uint8_t>(mtk_keytables[index][1].begin(), mtk_keytables[index][1].end());
    }
}

bool mtk_brutekey(std::ifstream& rf, std::vector<uint8_t>& out_aeskey, std::vector<uint8_t>& out_aesiv) {
    rf.seekg(0, std::ios::beg);
    uint8_t encdata[16];
    rf.read((char*)encdata, 16);
    
    for (size_t i = 0; i < mtk_keytables.size(); i++) {
        std::vector<uint8_t> aeskey, aesiv;
        mtk_getkey(i, aeskey, aesiv);
        
        uint8_t data[16];
        memcpy(data, encdata, 16);
        aes_cfb_decrypt(data, 16, aeskey.data(), aesiv.data());
        
        if (data[0] == 'M' && data[1] == 'M' && data[2] == 'M') {
            out_aeskey = aeskey;
            out_aesiv = aesiv;
            return true;
        }
    }
    return false;
}

std::string clean_cstring(const char* input, size_t max_len) {
    std::string s;
    for (size_t i = 0; i < max_len && input[i] != '\0'; i++) {
        s += input[i];
    }
    return s;
}

#pragma pack(push, 1)
struct OFPHeader {
    char prjname[46];
    uint64_t unknownval;
    char reserved[4];
    char cpu[7];
    char flashtype[5];
    uint16_t hdr2entries;
    char prjinfo[32];
    uint16_t crc;
};

struct OFPEntry {
    char name[32];
    uint64_t start;
    uint64_t length;
    uint64_t enclength;
    char filename[32];
    uint64_t crc;
};
#pragma pack(pop)

bool extract_mtk(std::ifstream& rf, std::streamsize filesize, const std::string& outdir) {
    std::vector<uint8_t> aeskey, aesiv;
    if (!mtk_brutekey(rf, aeskey, aesiv)) {
        return false; // Not MTK or unknown key
    }
    
    std::cout << "[MTK] Key found! Extracting..." << std::endl;
    if (!fs::exists(outdir)) fs::create_directories(outdir);
    
    const size_t hdrlength = 0x6C;
    std::string hdrkey_str = "geyixue";
    std::vector<uint8_t> hdrkey(hdrkey_str.begin(), hdrkey_str.end());
    
    rf.seekg(filesize - hdrlength, std::ios::beg);
    std::vector<uint8_t> hdr_data(hdrlength);
    rf.read((char*)hdr_data.data(), hdrlength);
    mtk_shuffle(hdrkey.data(), hdrkey.size(), hdr_data.data(), hdrlength);
    
    OFPHeader* hdr = reinterpret_cast<OFPHeader*>(hdr_data.data());
    size_t hdr2length = hdr->hdr2entries * 0x60;
    
    std::cout << "  Project: " << clean_cstring(hdr->prjname, 46) << std::endl;
    std::cout << "  CPU: " << clean_cstring(hdr->cpu, 7) << std::endl;
    
    rf.seekg(filesize - hdr2length - hdrlength, std::ios::beg);
    std::vector<uint8_t> hdr2_data(hdr2length);
    rf.read((char*)hdr2_data.data(), hdr2length);
    mtk_shuffle(hdrkey.data(), hdrkey.size(), hdr2_data.data(), hdr2length);
    
    for (int i = 0; i < hdr->hdr2entries; i++) {
        OFPEntry* entry = reinterpret_cast<OFPEntry*>(hdr2_data.data() + i * 0x60);
        std::string fname = clean_cstring(entry->filename, 32);
        
        std::cout << "  -> Extracting: " << fname << std::endl;
        
        std::string out_path = outdir + "/" + fname;
        std::ofstream wf(out_path, std::ios::binary);
        
        uint64_t enclength = entry->enclength;
        uint64_t length = entry->length;
        
        if (enclength > 0) {
            rf.seekg(entry->start, std::ios::beg);
            size_t read_len = enclength;
            if (read_len % 16 != 0) read_len += (16 - (read_len % 16));
            std::vector<uint8_t> encdata(read_len, 0);
            rf.read((char*)encdata.data(), entry->enclength);
            
            aes_cfb_decrypt(encdata.data(), read_len, aeskey.data(), aesiv.data());
            wf.write((char*)encdata.data(), enclength);
            length -= enclength;
        }
        
        uint64_t remain = length;
        const size_t buf_size = 0x200000;
        std::vector<char> buffer(buf_size);
        while (remain > 0) {
            size_t size = (remain < buf_size) ? remain : buf_size;
            rf.read(buffer.data(), size);
            wf.write(buffer.data(), size);
            remain -= size;
        }
    }
    
    std::cout << "\nMTK Extraction completed!" << std::endl;
    return true;
}

// ----------------------------------------------------------------------
// QC Logic
// ----------------------------------------------------------------------

void qc_deobfuscate(const std::vector<uint8_t>& data, const std::vector<uint8_t>& mask, std::vector<uint8_t>& out) {
    out.resize(data.size());
    for (size_t i = 0; i < data.size(); i++) {
        uint8_t v = data[i] ^ mask[i % mask.size()];
        out[i] = ((v >> 4) | (v << 4)) & 0xFF; // ROL 4 for 8 bit
    }
}

const std::vector<std::vector<std::string>> qc_keys = {
    {"V1.4.17", "27827963787265EF89D126B69A495A21", "82C50203285A2CE7D8C3E198383CE94C", "422DD5399181E223813CD8ECDF2E4D72"},
    {"V1.6.17", "E11AA7BB558A436A8375FD15DDD4651F", "77DDF6A0696841F6B74782C097835169", "A739742384A44E8BA45207AD5C3700EA"},
    {"V1.5.13", "67657963787565E837D226B69A495D21", "F6C50203515A2CE7D8C3E1F938B7E94C", "42F2D5399137E2B2813CD8ECDF2F4D72"},
    {"V1.6.6", "3C2D518D9BF2E4279DC758CD535147C3", "87C74A29709AC1BF2382276C4E8DF232", "598D92E967265E9BCABE2469FE4A915E"},
    {"V1.7.2", "8FB8FB261930260BE945B841AEFA9FD4", "E529E82B28F5A2F8831D860AE39E425D", "8A09DA60ED36F125D64709973372C1CF"},
    {"V2.0.3", "E8AE288C0192C54BF10C5707E9C4705B", "D64FC385DCD52A3C9B5FBA8650F92EDA", "79051FD8D8B6297E2E4559E997F63B7F"}
};

bool qc_generatekey(std::ifstream& rf, std::streamsize filesize, uint64_t& out_pagesize, std::vector<uint8_t>& out_key, std::vector<uint8_t>& out_iv, std::vector<uint8_t>& out_xml_data) {
    uint64_t pagesize = 0;
    
    // Check pagesize
    for (uint64_t x : {0x200, 0x1000}) {
        rf.seekg(filesize - x + 0x10, std::ios::beg);
        uint32_t val;
        rf.read((char*)&val, 4);
        if (val == 0x7CEF) {
            pagesize = x;
            break;
        }
    }
    
    if (pagesize == 0) return false; // Not QC
    
    uint64_t xmloffset = filesize - pagesize;
    rf.seekg(xmloffset + 0x14, std::ios::beg);
    uint32_t off_mult, length;
    rf.read((char*)&off_mult, 4);
    rf.read((char*)&length, 4);
    uint64_t offset = (uint64_t)off_mult * pagesize;
    
    if (length < 200) length = (uint32_t)(xmloffset - offset - 0x57);
    
    rf.seekg(offset, std::ios::beg);
    std::vector<uint8_t> enc_data(length);
    rf.read((char*)enc_data.data(), length);
    
    for (const auto& dkey : qc_keys) {
        std::vector<uint8_t> mc = hex2bin(dkey[1]);
        std::vector<uint8_t> userkey = hex2bin(dkey[2]);
        std::vector<uint8_t> ivec = hex2bin(dkey[3]);
        
        std::vector<uint8_t> deobf_userkey, deobf_ivec;
        qc_deobfuscate(userkey, mc, deobf_userkey);
        qc_deobfuscate(ivec, mc, deobf_ivec);
        
        uint8_t md5_1[16], md5_2[16];
        md5(deobf_userkey.data(), deobf_userkey.size(), md5_1);
        md5(deobf_ivec.data(), deobf_ivec.size(), md5_2);
        
        std::string hex1 = bin2hex(md5_1, 16);
        std::string hex2 = bin2hex(md5_2, 16);
        
        std::vector<uint8_t> key(hex1.begin(), hex1.begin() + 16);
        std::vector<uint8_t> iv(hex2.begin(), hex2.begin() + 16);
        
        std::vector<uint8_t> data = enc_data;
        aes_cfb_decrypt(data.data(), data.size(), key.data(), iv.data());
        
        // Find "<?xml"
        std::string dec_str((char*)data.data(), data.size());
        if (dec_str.find("<?xml") != std::string::npos) {
            out_pagesize = pagesize;
            out_key = key;
            out_iv = iv;
            out_xml_data = data;
            return true;
        }
    }
    
    return false; // Unknown QC key
}

void qc_copysub(std::ifstream& rf, std::ofstream& wf, uint64_t start, uint64_t length) {
    rf.seekg(start, std::ios::beg);
    uint64_t remain = length;
    const size_t buf_size = 0x100000;
    std::vector<char> buffer(buf_size);
    while (remain > 0) {
        size_t size = (remain < buf_size) ? remain : buf_size;
        rf.read(buffer.data(), size);
        wf.write(buffer.data(), size);
        remain -= size;
    }
}

bool extract_qc(std::ifstream& rf, std::streamsize filesize, const std::string& outdir) {
    uint64_t pagesize = 0;
    std::vector<uint8_t> key, iv, xml_data;
    
    if (!qc_generatekey(rf, filesize, pagesize, key, iv, xml_data)) {
        return false;
    }
    
    std::cout << "[QC] Key found! Extracting..." << std::endl;
    if (!fs::exists(outdir)) fs::create_directories(outdir);
    
    std::string xml_str((char*)xml_data.data(), xml_data.size());
    size_t end_pos = xml_str.rfind(">");
    if (end_pos != std::string::npos) {
        xml_str = xml_str.substr(0, end_pos + 1);
    }
    
    std::string profile_path = outdir + "/ProFile.xml";
    std::ofstream prof(profile_path);
    prof << xml_str;
    prof.close();
    
    tinyxml2::XMLDocument doc;
    if (doc.Parse(xml_str.c_str()) != tinyxml2::XML_SUCCESS) {
        std::cerr << "Failed to parse ProFile.xml" << std::endl;
        return true;
    }
    
    tinyxml2::XMLElement* root = doc.RootElement();
    if (!root) return true;
    
    for (tinyxml2::XMLElement* child = root->FirstChildElement(); child != nullptr; child = child->NextSiblingElement()) {
        std::string tag = child->Name();
        
        // Items are either direct children or nested
        auto process_item = [&](tinyxml2::XMLElement* item) {
            std::string wfilename;
            if (item->Attribute("Path")) wfilename = item->Attribute("Path");
            else if (item->Attribute("filename")) wfilename = item->Attribute("filename");
            
            if (wfilename.empty()) return;
            
            int64_t start = -1;
            if (item->Attribute("FileOffsetInSrc")) {
                start = std::stoll(item->Attribute("FileOffsetInSrc")) * pagesize;
            } else if (item->Attribute("SizeInSectorInSrc")) { // This matches python logic but is strange
                if (!item->Attribute("FileOffsetInSrc")) {
                   // Some nodes have it different
                   if (item->Attribute("StartSectorInSrc")) {
                       start = std::stoll(item->Attribute("StartSectorInSrc")) * pagesize;
                   }
                }
            }
            if (start == -1 && item->Attribute("SizeInSectorInSrc")) {
                // from python logic: elif "SizeInSectorInSrc" in item.attrib: start = int(item.attrib["SizeInSectorInSrc"]) * pagesize 
                // Note: The python script does this, which looks like a typo in their code, but we will adapt.
                start = std::stoll(item->Attribute("SizeInSectorInSrc")) * pagesize;
            }
            
            int64_t rlength = 0;
            if (item->Attribute("SizeInByteInSrc")) {
                rlength = std::stoll(item->Attribute("SizeInByteInSrc"));
            }
            
            int64_t length = rlength;
            if (item->Attribute("SizeInSectorInSrc")) {
                length = std::stoll(item->Attribute("SizeInSectorInSrc")) * pagesize;
            }
            
            if (start == -1) return;
            
            int64_t decryptsize = 0x40000;
            if (tag == "Sahara") decryptsize = rlength;
            if (tag == "Config" || tag == "Provision" || tag == "ChainedTableOfDigests" || tag == "DigestsToSign" || tag == "Firmware") {
                length = rlength;
            }
            
            std::cout << "  -> Extracting: " << wfilename << std::endl;
            std::string out_path = outdir + "/" + wfilename;
            std::ofstream wf(out_path, std::ios::binary);
            
            if (tag == "DigestsToSign" || tag == "ChainedTableOfDigests" || tag == "Firmware") {
                // Copy without decrypt
                qc_copysub(rf, wf, start, length);
            } else {
                // Decryptfile
                if (rlength == length) {
                    int64_t tlen = length;
                    length = (length / 4) * 4;
                    if (tlen % 4 != 0) length += 4;
                }
                
                rf.seekg(start, std::ios::beg);
                int64_t size = std::min(rlength, decryptsize);
                
                int64_t read_size = size;
                if (read_size % 4 != 0) read_size += (4 - (read_size % 4));
                
                std::vector<uint8_t> enc_data(read_size, 0);
                rf.read((char*)enc_data.data(), size);
                
                aes_cfb_decrypt(enc_data.data(), read_size, key.data(), iv.data());
                wf.write((char*)enc_data.data(), size);
                
                if (rlength > decryptsize) {
                    qc_copysub(rf, wf, start + size, rlength - size);
                }
            }
        };
        
        if (child->NoChildren() || child->FirstChildElement() == nullptr) {
            process_item(child);
        } else {
            for (tinyxml2::XMLElement* item = child->FirstChildElement(); item != nullptr; item = item->NextSiblingElement()) {
                if (!item->Attribute("Path") && !item->Attribute("filename")) {
                    for (tinyxml2::XMLElement* subitem = item->FirstChildElement(); subitem != nullptr; subitem = subitem->NextSiblingElement()) {
                        process_item(subitem);
                    }
                } else {
                    process_item(item);
                }
            }
        }
    }
    
    std::cout << "\nQC Extraction completed!" << std::endl;
    return true;
}

// ----------------------------------------------------------------------
// Main
// ----------------------------------------------------------------------

int main(int argc, char** argv) {
    std::cout << "========================================\n";
    std::cout << "  Oppo OFP Decryptor C++ (MTK/QC)\n";
    std::cout << "========================================\n\n";

    std::string filename;
    std::string outdir;

    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <filename.ofp> [outdir]" << std::endl;
        std::cout << "Or simply DRAG AND DROP an .ofp file onto this executable." << std::endl;
        std::cout << "\nPress Enter to exit...";
        std::cin.get();
        return 1;
    }
    
    filename = argv[1];
    
    if (argc >= 3) {
        outdir = argv[2];
    } else {
        // Auto-generate output directory for drag-and-drop
        fs::path p(filename);
        outdir = (p.parent_path() / (p.stem().string() + "_extracted")).string();
        std::cout << "Output directory not specified, using default:\n" << outdir << "\n\n";
    }
    
    std::ifstream rf(filename, std::ios::binary | std::ios::ate);
    if (!rf) {
        std::cerr << "Cannot open file: " << filename << std::endl;
        if (argc == 2) {
            std::cout << "\nPress Enter to exit...";
            std::cin.get();
        }
        return 1;
    }
    
    std::streamsize filesize = rf.tellg();
    bool success = false;
    
    // Try QC first since it has a clear 0x7CEF signature
    std::cout << "Checking QC format..." << std::endl;
    if (extract_qc(rf, filesize, outdir)) {
        success = true;
    } else {
        // Fallback to MTK
        std::cout << "Checking MTK format..." << std::endl;
        if (extract_mtk(rf, filesize, outdir)) {
            success = true;
        }
    }
    
    if (!success) {
        std::cerr << "\nError: File format not recognized or key not found." << std::endl;
    }
    
    // Pause if run via drag and drop
    if (argc == 2) {
        std::cout << "\nPress Enter to exit...";
        std::cin.get();
    }
    
    return success ? 0 : 1;
}
