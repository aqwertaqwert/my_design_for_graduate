#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xa8c16cf3, "module_layout" },
	{ 0x88129f86, "misc_deregister" },
	{ 0x4302d0eb, "free_pages" },
	{ 0xff141e17, "misc_register" },
	{ 0xfb578fc5, "memset" },
	{ 0x4f8b5ddb, "_copy_to_user" },
	{ 0xa1c76e0a, "_cond_resched" },
	{ 0x27e1a049, "printk" },
	{ 0x1c2e11b9, "__get_page_tail" },
	{ 0xe52947e7, "__phys_addr" },
	{ 0x9f6e19ab, "mem_section" },
	{ 0x69a358a6, "iomem_resource" },
	{ 0x9b388444, "get_zeroed_page" },
	{ 0xb4390f9a, "mcount" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "3757D31E72E41E7A5BA1CD6");
