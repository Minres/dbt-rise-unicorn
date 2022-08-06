/*******************************************************************************
 * Copyright 2022 MINRES Technologies GmbH
 * SPDX-License-Identifier: Apache-2.0
 *******************************************************************************/

#define SC_INCLUDE_DYNAMIC_PROCESSES

#include "unicorn_sc.h"
#include "core_impl.h"
#include <iss/debugger_if.h>
#include <iss/debugger/server.h>
#include <iss/debugger/gdb_session.h>
#include <iss/debugger/target_adapter_base.h>

core_impl::~core_impl(){
    if(uc) uc_close(uc);
}

iss::debugger::target_adapter_if *core_impl::accquire_target_adapter(iss::debugger::server_if *server){
    if(!tgt_adapt)
        tgt_adapt.reset(new target_adapter(server, this));
    return tgt_adapt.get();
}


void unicorn_sc::run() {
    wait(sc_core::SC_ZERO_TIME);
    auto addr=start_address.value;
    while(true){
        if(reset_i.read()) {
            addr=start_address.value;
            wait(reset_i.negedge_event());
            impl->set_pc(addr);
        }
        impl->limit+=1000;
        if (auto err = uc_emu_start(impl->uc, addr, std::numeric_limits<uint64_t>::max(), 0, 0)) {
            std::stringstream ss;
            ss<<"Failed on uc_emu_start() with error returned: "<<err<<" ("<<uc_strerror(err)<<") at pc=0x"<<std::hex<<impl->get_pc();
            SC_REPORT_FATAL(name(), ss.str().c_str());
        }
        addr=impl->get_pc();
        wait(100*clk_i.read());
    }
}

unicorn_sc::unicorn_sc(const sc_core::sc_module_name &name, size_t num_internal_mems, size_t num_external_mems)
: sc_core::sc_module(name)
, internal_mem_start("internal_mem_start", num_internal_mems)
, internal_mem_size("internal_mem_size", num_internal_mems)
, external_mem_start("external_mem_start", num_external_mems)
, external_mem_size("external_mem_size", num_external_mems)
, impl(new core_impl(*this))
{
    add_attribute(arch);
    add_attribute(mode);
    add_attribute(model);
    for(auto&a:internal_mem_start) add_attribute(a);
    for(auto&a:internal_mem_size) add_attribute(a);
    for(auto&a:external_mem_start) add_attribute(a);
    for(auto&a:external_mem_size) add_attribute(a);
    add_attribute(start_address);
    add_attribute(debug_server_port);

    sc_core::sc_spawn([this](){run();});
    isckt.bind(*impl);
}

unicorn_sc::~unicorn_sc() {
}

void unicorn_sc::before_end_of_elaboration() {
    impl->beoe();
    if(debug_server_port.value)
        iss::debugger::server<iss::debugger::gdb_session>::run_server(impl.get(), debug_server_port.value);
}

void unicorn_sc::end_of_elaboration() {}

void unicorn_sc::start_of_simulation() {}

bool unicorn_sc::write_internal_memory(uint64_t addr, uint64_t size, const unsigned char *data) {
    return uc_mem_write(impl->uc, addr, data, size-1) == UC_ERR_OK;
}

void unicorn_sc::end_of_simulation() {
    uc_close(impl->uc);
    impl->uc=nullptr;

}
