/*
 * target_adapter.cpp
 *
 *  Created on: 06.08.2022
 *      Author: eyck
 */

#include "target_adapter.h"
#include "core_impl.h"
#include <unicorn/unicorn.h>
#include <fmt/format.h>
#include <util/logging.h>

inline iss::status target_adapter::set_gen_thread(rp_thread_ref &thread) {
    thread_idx = thread;
    return iss::Ok;
}

inline iss::status target_adapter::set_ctrl_thread(rp_thread_ref &thread) {
    thread_idx = thread;
    return iss::Ok;
}

inline iss::status target_adapter::is_thread_alive(rp_thread_ref &thread,
        bool &alive) {
    alive=true;
    return iss::Ok;
}

inline iss::status target_adapter::thread_list_query(int first,
        const rp_thread_ref &arg, std::vector<rp_thread_ref> &result,
        size_t max_num, size_t &num, bool &done) {
    if (first == 0) {
        result.clear();
        result.push_back(thread_idx);
        num = 1;
        done = true;
        return iss::Ok;
    } else
        return iss::NotSupported;
}

inline iss::status target_adapter::current_thread_query(rp_thread_ref &thread) {
    thread = thread_idx;
    return iss::Ok;
}

struct reg_descriptor {
    unsigned offset;
    unsigned size;
    std::string name;
};
std::vector<reg_descriptor> get_reg_definition(uc_engine* uc){
    uc_arch arch;
    uc_ctl_get_arch(uc, &arch);
    switch (arch) {
    default:
        //    case UC_ARCH_M68K:
        //    case UC_ARCH_X86:
        //    case UC_ARCH_MIPS:
        //    case UC_ARCH_SPARC:
        //    case UC_ARCH_PPC:
        //    case UC_ARCH_S390X:
        return {};
    case UC_ARCH_ARM:
        return {
            {UC_ARM_REG_R0, 4, "R0"},
            {UC_ARM_REG_R1, 4, "R1"},
            {UC_ARM_REG_R2, 4, "R2"},
            {UC_ARM_REG_R3, 4, "R3"},
            {UC_ARM_REG_R4, 4, "R4"},
            {UC_ARM_REG_R5, 4, "R5"},
            {UC_ARM_REG_R6, 4, "R6"},
            {UC_ARM_REG_R7, 4, "R7"},
            {UC_ARM_REG_R8, 4, "R8"},
            {UC_ARM_REG_R9, 4, "R9"},
            {UC_ARM_REG_R10,4, "R10"},
            {UC_ARM_REG_R11,4, "R11"},
            {UC_ARM_REG_R12,4, "R12"},
            {UC_ARM_REG_R13, 4, "R13"},
            {UC_ARM_REG_R14, 4, "R14"},
            {UC_ARM_REG_R15, 4, "R15"}
        };
        break;
    case UC_ARCH_ARM64:
        return {
            {UC_ARM64_REG_X0,  8, "X0"},
            {UC_ARM64_REG_X1,  8, "X1"},
            {UC_ARM64_REG_X2,  8, "X2"},
            {UC_ARM64_REG_X3,  8, "X3"},
            {UC_ARM64_REG_X4,  8, "X4"},
            {UC_ARM64_REG_X5,  8, "X5"},
            {UC_ARM64_REG_X6,  8, "X6"},
            {UC_ARM64_REG_X7,  8, "X7"},
            {UC_ARM64_REG_X8,  8, "X8"},
            {UC_ARM64_REG_X9,  8, "X9"},
            {UC_ARM64_REG_X10, 8, "X10"},
            {UC_ARM64_REG_X11, 8, "X11"},
            {UC_ARM64_REG_X12, 8, "X12"},
            {UC_ARM64_REG_X13, 8, "X13"},
            {UC_ARM64_REG_X14, 8, "X14"},
            {UC_ARM64_REG_X15, 8, "X15"},
            {UC_ARM64_REG_X16, 8, "X16"},
            {UC_ARM64_REG_X17, 8, "X17"},
            {UC_ARM64_REG_X18, 8, "X18"},
            {UC_ARM64_REG_X19, 8, "X19"},
            {UC_ARM64_REG_X20, 8, "X20"},
            {UC_ARM64_REG_X21, 8, "X21"},
            {UC_ARM64_REG_X22, 8, "X22"},
            {UC_ARM64_REG_X23, 8, "X23"},
            {UC_ARM64_REG_X24, 8, "X24"},
            {UC_ARM64_REG_X25, 8, "X25"},
            {UC_ARM64_REG_X26, 8, "X26"},
            {UC_ARM64_REG_X27, 8, "X27"},
            {UC_ARM64_REG_X28, 8, "X28"},
            {UC_ARM64_REG_X29, 8, "X29"},
            {UC_ARM64_REG_X30, 8, "X30"},
            {UC_ARM64_REG_SP, 8, "SP"},
            {UC_ARM64_REG_PC, 8, "PC"}
        };
        break;
    case UC_ARCH_RISCV:
        uc_mode mode;
        uc_ctl_get_mode(uc, &mode);
        switch(mode){
        default: return {};
        case UC_MODE_RISCV32:
            return {
                {UC_RISCV_REG_X0, 4, "X0"},
                {UC_RISCV_REG_X1, 4, "X1"},
                {UC_RISCV_REG_X2, 4, "X2"},
                {UC_RISCV_REG_X3, 4, "X3"},
                {UC_RISCV_REG_X4, 4, "X4"},
                {UC_RISCV_REG_X5, 4, "X5"},
                {UC_RISCV_REG_X6, 4, "X6"},
                {UC_RISCV_REG_X7, 4, "X7"},
                {UC_RISCV_REG_X8, 4, "X8"},
                {UC_RISCV_REG_X9, 4, "X9"},
                {UC_RISCV_REG_X10,4, "X10"},
                {UC_RISCV_REG_X11,4, "X11"},
                {UC_RISCV_REG_X12,4, "X12"},
                {UC_RISCV_REG_X13,4, "X13"},
                {UC_RISCV_REG_X14,4, "X14"},
                {UC_RISCV_REG_X15,4, "X15"},
                {UC_RISCV_REG_X16,4, "X16"},
                {UC_RISCV_REG_X17,4, "X17"},
                {UC_RISCV_REG_X18,4, "X18"},
                {UC_RISCV_REG_X19,4, "X19"},
                {UC_RISCV_REG_X20,4, "X20"},
                {UC_RISCV_REG_X21,4, "X21"},
                {UC_RISCV_REG_X22,4, "X22"},
                {UC_RISCV_REG_X23,4, "X23"},
                {UC_RISCV_REG_X24,4, "X24"},
                {UC_RISCV_REG_X25,4, "X25"},
                {UC_RISCV_REG_X26,4, "X26"},
                {UC_RISCV_REG_X27,4, "X27"},
                {UC_RISCV_REG_X28,4, "X28"},
                {UC_RISCV_REG_X29,4, "X29"},
                {UC_RISCV_REG_X30,4, "X30"},
                {UC_RISCV_REG_X31,4, "X31"},
                {UC_RISCV_REG_PC, 4, "PC"}
            };
        case UC_MODE_RISCV64:
            return {
                {UC_RISCV_REG_X0, 8, "X0"},
                {UC_RISCV_REG_X1, 8, "X1"},
                {UC_RISCV_REG_X2, 8, "X2"},
                {UC_RISCV_REG_X3, 8, "X3"},
                {UC_RISCV_REG_X4, 8, "X4"},
                {UC_RISCV_REG_X5, 8, "X5"},
                {UC_RISCV_REG_X6, 8, "X6"},
                {UC_RISCV_REG_X7, 8, "X7"},
                {UC_RISCV_REG_X8, 8, "X8"},
                {UC_RISCV_REG_X9, 8, "X9"},
                {UC_RISCV_REG_X10,8, "X10"},
                {UC_RISCV_REG_X11,8, "X11"},
                {UC_RISCV_REG_X12,8, "X12"},
                {UC_RISCV_REG_X13,8, "X13"},
                {UC_RISCV_REG_X14,8, "X14"},
                {UC_RISCV_REG_X15,8, "X15"},
                {UC_RISCV_REG_X16,8, "X16"},
                {UC_RISCV_REG_X17,8, "X17"},
                {UC_RISCV_REG_X18,8, "X18"},
                {UC_RISCV_REG_X19,8, "X19"},
                {UC_RISCV_REG_X20,8, "X20"},
                {UC_RISCV_REG_X21,8, "X21"},
                {UC_RISCV_REG_X22,8, "X22"},
                {UC_RISCV_REG_X23,8, "X23"},
                {UC_RISCV_REG_X24,8, "X24"},
                {UC_RISCV_REG_X25,8, "X25"},
                {UC_RISCV_REG_X26,8, "X26"},
                {UC_RISCV_REG_X27,8, "X27"},
                {UC_RISCV_REG_X28,8, "X28"},
                {UC_RISCV_REG_X29,8, "X29"},
                {UC_RISCV_REG_X30,8, "X30"},
                {UC_RISCV_REG_X31,8, "X31"},
                {UC_RISCV_REG_PC, 8, "PC"}
            };
        }
    }

}
inline iss::status target_adapter::read_registers(std::vector<uint8_t> &data,
        std::vector<uint8_t> &avail) {
    auto register_definition = get_reg_definition(core->uc);
    unsigned len=0;
    for(auto& def: register_definition)
        len+=def.size;
    data.resize(len);
    avail.resize(len);
    uint8_t* data_ptr = data.data();
    uint8_t* avail_ptr = avail.data();
    for(auto& def: register_definition) {
        uc_reg_read(core->uc, def.offset, data_ptr);
        data_ptr+=def.size;
        for(size_t i=0; i<def.size; ++i, avail_ptr++) *avail_ptr = 0xff;
    }
    return iss::Ok;
}

inline iss::status target_adapter::write_registers(const std::vector<uint8_t> &data) {
    auto register_definition = get_reg_definition(core->uc);
    unsigned len=0;
    for(auto& def: register_definition)
        len+=def.size;
    assert(data.size()==len);
    uint8_t const* data_ptr = data.data();
    unsigned i=0;
    for(auto& def: register_definition) {
        uc_reg_write(core->uc, def.offset, data_ptr);
        data_ptr+=def.size;
    }
    return iss::Ok;
}

inline iss::status target_adapter::read_single_register(unsigned int reg_no,
        std::vector<uint8_t> &buf, std::vector<uint8_t> &avail_buf) {
    uc_reg_read(core->uc, reg_no, buf.data());
    return iss::Ok;
}

inline iss::status target_adapter::write_single_register(unsigned int reg_no,
        const std::vector<uint8_t> &buf) {
    uc_reg_write(core->uc, reg_no, buf.data());
    return iss::Ok;
}

inline iss::status target_adapter::read_mem(uint64_t addr, std::vector<uint8_t> &buf) {
    return uc_mem_read(core->uc, addr, buf.data(), buf.size()-1) == UC_ERR_OK?iss::Ok:iss::Err;
}

inline iss::status target_adapter::write_mem(uint64_t addr, const std::vector<uint8_t> &buf) {
    return uc_mem_write(core->uc, addr, buf.data(), buf.size()-1) == UC_ERR_OK?iss::Ok:iss::Err;
}

inline iss::status target_adapter::process_query(unsigned int &mask,
        const rp_thread_ref &arg, iss::debugger::rp_thread_info &info) {
    return iss::NotSupported;
}

inline iss::status target_adapter::offsets_query(uint64_t &text, uint64_t &data,
        uint64_t &bss) {
    text = 0;
    data = 0;
    bss = 0;
    return iss::Ok;
}

inline iss::status target_adapter::crc_query(uint64_t addr, size_t len,
        uint32_t &val) {
    return iss::NotSupported;
}

inline iss::status target_adapter::raw_query(std::string in_buf,
        std::string &out_buf) {
    return iss::NotSupported;
}

inline iss::status target_adapter::threadinfo_query(int first,
        std::string &out_buf) {
    if (first) {
        out_buf = fmt::format("m{:x}", thread_idx.val);
    } else {
        out_buf = "l";
    }
    return iss::Ok;
}

inline iss::status target_adapter::threadextrainfo_query(
        const rp_thread_ref &thread, std::string &out_buf) {
    std::array<char, 20> buf;
    memset(buf.data(), 0, 20);
    sprintf(buf.data(), "%02x%02x%02x%02x%02x%02x%02x%02x%02x", 'R', 'u', 'n', 'n', 'a', 'b', 'l', 'e', 0);
    out_buf = buf.data();
    return iss::Ok;
}

inline iss::status target_adapter::packetsize_query(std::string &out_buf) {
    out_buf = "PacketSize=1000";
    return iss::Ok;
}

inline iss::status target_adapter::add_break(break_type type, uint64_t addr,
        unsigned int length) {
    switch(type) {
    default:
        return iss::Err;
    case SW_EXEC:
    case HW_EXEC: {
        target_adapter_base::bp_lut.addEntry(++target_adapter_base::bp_count,addr, length);
        LOG(TRACE) << "Adding breakpoint with handle " << target_adapter_base::bp_count << " for addr 0x" << std::hex
                << addr << std::dec;
        LOG(TRACE) << "Now having " << target_adapter_base::bp_lut.size() << " breakpoints";
        return iss::Ok;
    }
    }
}

inline iss::status target_adapter::remove_break(break_type type, uint64_t addr, unsigned int length) {
    switch(type) {
    default:
        return iss::Err;
    case SW_EXEC:
    case HW_EXEC: {
        unsigned handle = target_adapter_base::bp_lut.getEntry(addr);
        if (handle) {
            LOG(TRACE) << "Removing breakpoint with handle " << handle << " for addr 0x" << std::hex << addr
                    << std::dec;
            // TODO: check length of addr range
            target_adapter_base::bp_lut.removeEntry(handle);
            LOG(TRACE) << "Now having " << target_adapter_base::bp_lut.size() << " breakpoints";
            return iss::Ok;
        }
        LOG(TRACE) << "Now having " << target_adapter_base::bp_lut.size() << " breakpoints";
        return iss::Err;
    }
    }
}

inline iss::status target_adapter::resume_from_addr(bool step, int sig,
        uint64_t addr, rp_thread_ref thread,
        std::function<void(unsigned)> stop_callback) {
    core->set_pc(addr);
    return resume_from_current(step, sig, thread, stop_callback);
}

inline iss::status target_adapter::target_xml_query(std::string &out_buf) {
    //TODO: implement method
    return iss::NotSupported;
}
