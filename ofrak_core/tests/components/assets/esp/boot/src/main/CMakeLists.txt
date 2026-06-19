idf_component_register(SRCS "app_main.c" "target.c" INCLUDE_DIRS ".")

# On RISC-V, build this component without the compressed ("C") extension so app_main's call to
# target() is a full 4-byte `jal` (+/-1MB reach) instead of a 2-byte `c.jal` (only +/-2KB). That
# lets the OFRAK test rewrite the call in place to reach the injected patch. No effect on Xtensa;
# the injected patch itself is still compiled with the stock ESP toolchain.
if(CONFIG_IDF_TARGET_ARCH_RISCV)
    target_compile_options(${COMPONENT_LIB} PRIVATE "-march=rv32ima_zicsr_zifencei")
endif()
