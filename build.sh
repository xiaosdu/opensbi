export ARCH=riscv
export CROSS_COMPILE=riscv64-linux-gnu-
export CC="${CROSS_COMPILE}gcc -mabi=lp64d -march=rv64gc"
make PLATFORM=generic PLATFORM_RISCV_XLEN=64 DEBUG=1
rm -rf /home/xiao/Documents/kvm/qemu/pc-bios/opensbi-riscv64-generic-fw_dynamic.bin
cp ./build/platform/generic/firmware/fw_dynamic.bin \
 ../qemu/pc-bios/opensbi-riscv64-generic-fw_dynamic.bin
