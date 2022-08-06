/*
 * target_adapter.h
 *
 *  Created on: 06.08.2022
 *      Author: eyck
 */

#ifndef DBT_RISE_UNICORN_SRC_TARGET_ADAPTER_H_
#define DBT_RISE_UNICORN_SRC_TARGET_ADAPTER_H_

#include "unicorn_sc.h"
#include <iss/debugger/target_adapter_base.h>

struct core_impl;

struct target_adapter: public iss::debugger::target_adapter_base {
    using rp_thread_ref= iss::debugger::rp_thread_ref;

    target_adapter(iss::debugger::server_if *srv, core_impl* core)
    : iss::debugger::target_adapter_base(srv), core(core){}
    /*============== Thread Control ===============================*/

    /* Set generic thread */
    iss::status set_gen_thread(rp_thread_ref &thread) override;

    /* Set control thread */
    iss::status set_ctrl_thread(rp_thread_ref &thread) override;

    /* Get thread status */
    iss::status is_thread_alive(rp_thread_ref &thread, bool &alive) override;

    /*============= Register Access ================================*/

    /* Read all registers. buf is 4-byte aligned and it is in
     target byte order. If  register is not available
     corresponding bytes in avail_buf are 0, otherwise
     avail buf is 1 */
    iss::status read_registers(std::vector<uint8_t> &data, std::vector<uint8_t> &avail) override;

    /* Write all registers. buf is 4-byte aligned and it is in target
     byte order */
    iss::status write_registers(const std::vector<uint8_t> &data) override;

    /* Read one register. buf is 4-byte aligned and it is in
     target byte order. If  register is not available
     corresponding bytes in avail_buf are 0, otherwise
     avail buf is 1 */
    iss::status read_single_register(unsigned int reg_no, std::vector<uint8_t> &buf,
            std::vector<uint8_t> &avail_buf) override;

    /* Write one register. buf is 4-byte aligned and it is in target byte
     order */
    iss::status write_single_register(unsigned int reg_no, const std::vector<uint8_t> &buf) override;

    /*=================== Memory Access =====================*/

    /* Read memory, buf is 4-bytes aligned and it is in target
     byte order */
    iss::status read_mem(uint64_t addr, std::vector<uint8_t> &buf) override;

    /* Write memory, buf is 4-bytes aligned and it is in target
     byte order */
    iss::status write_mem(uint64_t addr, const std::vector<uint8_t> &buf) override;

    iss::status process_query(unsigned int &mask, const rp_thread_ref &arg, iss::debugger::rp_thread_info &info) override;

    iss::status thread_list_query(int first, const rp_thread_ref &arg, std::vector<rp_thread_ref> &result, size_t max_num,
            size_t &num, bool &done) override;

    iss::status current_thread_query(rp_thread_ref &thread) override;

    iss::status offsets_query(uint64_t &text, uint64_t &data, uint64_t &bss) override;

    iss::status crc_query(uint64_t addr, size_t len, uint32_t &val) override;

    iss::status raw_query(std::string in_buf, std::string &out_buf) override;

    iss::status threadinfo_query(int first, std::string &out_buf) override;

    iss::status threadextrainfo_query(const rp_thread_ref &thread, std::string &out_buf) override;

    iss::status packetsize_query(std::string &out_buf) override;

    iss::status add_break(break_type type, uint64_t addr, unsigned int length) override;

    iss::status remove_break(break_type type, uint64_t addr, unsigned int length) override;

    iss::status resume_from_addr(bool step, int sig, uint64_t addr, rp_thread_ref thread,
            std::function<void(unsigned)> stop_callback) override;

    iss::status target_xml_query(std::string &out_buf) override;

protected:
    core_impl *core{nullptr};
    rp_thread_ref thread_idx;
};



#endif /* DBT_RISE_UNICORN_SRC_TARGET_ADAPTER_H_ */
