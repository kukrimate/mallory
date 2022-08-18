// SPDX-License-Identifier: BSD-2-Clause-Patent

	.section .text.kernel, "a", %progbits
	.balignl 4096, 0
	.globl	_kernel_start
	.type	_kernel_start, %object
	.size	_kernel_start, 1
_kernel_start:
	.globl	shim_kernel_image
	.type	shim_kernel_image, %object
	.size	shim_kernel_image, _kernel_end - shim_kernel_image
shim_kernel_image:
#if defined(SHIM_KERNEL_FILE)
	.incbin	SHIM_KERNEL_FILE
#endif
	.globl	_kernel_end
	.type	_kernel_end, %object
	.size	_kernel_end, 1
_kernel_end:

	.section .data.initrd, "a", %progbits
	.balignl 4096, 0
	.globl	_initrd_start
	.type	_initrd_start, %object
	.size	_initrd_start, 1
_initrd_start:
	.globl	shim_initrd_image
	.type	shim_initrd_image, %object
	.size	shim_initrd_image, _initrd_end - shim_initrd_image
shim_initrd_image:
#if defined(SHIM_INITRD_FILE)
	.incbin	SHIM_INITRD_FILE
#endif
	.globl	_initrd_end
	.type	_initrd_end, %object
	.size	_initrd_end, 1
_initrd_end:
