// SPDX-License-Identifier: BSD-2-Clause-Patent
/*
 * hash.c - a authenticode simple hash utility
 */

#define _GNU_SOURCE 1

#include <errno.h>
#include <err.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/sha.h>

#include <efi.h>

#define AllocatePool(x) calloc(1, x)
#define AllocateZeroPool(x) calloc(1, x)
#define FreePool(x) free(x)
#define CopyMem(dest, src, size) memcpy(dest, src, size)

#define perror(fmt, ...) printf(fmt, ##__VA_ARGS__)
#define dprint(fmt, ...) printf(fmt, ##__VA_ARGS__)

#define UNUSED __attribute__((__unused__))

#include "include/peimage.h"
#include "include/pe.h"


UINTN
Sha256GetContextSize(VOID)
{
	return (UINTN)(sizeof(SHA256_CTX));
}

BOOLEAN
Sha256Init(OUT VOID *Sha256Context)
{
	if (Sha256Context == NULL) {
		return FALSE;
	}

	return (BOOLEAN)(SHA256_Init((SHA256_CTX *)Sha256Context));
}

BOOLEAN
Sha256Duplicate(IN CONST VOID *Sha256Context, OUT VOID *NewSha256Context)
{
	if (Sha256Context == NULL || NewSha256Context == NULL) {
		return FALSE;
	}

	CopyMem(NewSha256Context, Sha256Context, sizeof(SHA256_CTX));

	return TRUE;
}

BOOLEAN
Sha256Update(IN OUT VOID *Sha256Context, IN CONST VOID *Data, IN UINTN DataSize)
{
	if (Sha256Context == NULL) {
		return FALSE;
	}

	if (Data == NULL && DataSize != 0) {
		return FALSE;
	}

	return (BOOLEAN)(
		SHA256_Update((SHA256_CTX *)Sha256Context, Data, DataSize));
}

BOOLEAN
EFIAPI
Sha256Final(IN OUT VOID *Sha256Context, OUT UINT8 *HashValue)
{
	if (Sha256Context == NULL || HashValue == NULL) {
		return FALSE;
	}

	return (BOOLEAN)(SHA256_Final(HashValue, (SHA256_CTX *)Sha256Context));
}

static int
image_is_64_bit(EFI_IMAGE_OPTIONAL_HEADER_UNION *PEHdr)
{
	/* .Magic is the same offset in all cases */
	if (PEHdr->Pe32Plus.OptionalHeader.Magic
			== EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		return 1;
	return 0;
}

static int
image_is_loadable(EFI_IMAGE_OPTIONAL_HEADER_UNION *PEHdr)
{
	/* If it's not a header type we recognize at all, bail */
	switch (PEHdr->Pe32Plus.OptionalHeader.Magic) {
	case EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC:
	case EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC:
		break;
	default:
		return 0;
	}
	return 1;
}

void *
ImageAddress (void *image, uint64_t size, uint64_t address)
{
	/* ensure our local pointer isn't bigger than our size */
	if (address > size)
		return NULL;

	/* Insure our math won't overflow */
	if (UINT64_MAX - address < (uint64_t)(intptr_t)image)
		return NULL;

	/* return the absolute pointer */
	return image + address;
}

EFI_STATUS
read_header(void *data, unsigned int datasize,
	    PE_COFF_LOADER_IMAGE_CONTEXT *context)
{
	EFI_IMAGE_DOS_HEADER *DosHdr = data;
	EFI_IMAGE_OPTIONAL_HEADER_UNION *PEHdr = data;
	unsigned long HeaderWithoutDataDir, SectionHeaderOffset, OptHeaderSize;
	unsigned long FileAlignment = 0;

	if (datasize < sizeof (PEHdr->Pe32)) {
		perror("Invalid image\n");
		return EFI_UNSUPPORTED;
	}

	if (DosHdr->e_magic == EFI_IMAGE_DOS_SIGNATURE)
		PEHdr = (EFI_IMAGE_OPTIONAL_HEADER_UNION *)((char *)data + DosHdr->e_lfanew);

	if (!image_is_loadable(PEHdr)) {
		perror("Platform does not support this image\n");
		return EFI_UNSUPPORTED;
	}

	if (image_is_64_bit(PEHdr)) {
		context->NumberOfRvaAndSizes = PEHdr->Pe32Plus.OptionalHeader.NumberOfRvaAndSizes;
		context->SizeOfHeaders = PEHdr->Pe32Plus.OptionalHeader.SizeOfHeaders;
		context->ImageSize = PEHdr->Pe32Plus.OptionalHeader.SizeOfImage;
		context->SectionAlignment = PEHdr->Pe32Plus.OptionalHeader.SectionAlignment;
		FileAlignment = PEHdr->Pe32Plus.OptionalHeader.FileAlignment;
		OptHeaderSize = sizeof(EFI_IMAGE_OPTIONAL_HEADER64);
	} else {
		context->NumberOfRvaAndSizes = PEHdr->Pe32.OptionalHeader.NumberOfRvaAndSizes;
		context->SizeOfHeaders = PEHdr->Pe32.OptionalHeader.SizeOfHeaders;
		context->ImageSize = (UINT64)PEHdr->Pe32.OptionalHeader.SizeOfImage;
		context->SectionAlignment = PEHdr->Pe32.OptionalHeader.SectionAlignment;
		FileAlignment = PEHdr->Pe32.OptionalHeader.FileAlignment;
		OptHeaderSize = sizeof(EFI_IMAGE_OPTIONAL_HEADER32);
	}

	if (FileAlignment % 2 != 0) {
		perror("File Alignment is invalid (%lu)\n", FileAlignment);
		return EFI_UNSUPPORTED;
	}
	if (FileAlignment == 0)
		FileAlignment = 0x200;
	if (context->SectionAlignment == 0)
		context->SectionAlignment = sysconf(_SC_PAGE_SIZE);
	if (context->SectionAlignment < FileAlignment)
		context->SectionAlignment = FileAlignment;

	context->NumberOfSections = PEHdr->Pe32.FileHeader.NumberOfSections;

	if (EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES < context->NumberOfRvaAndSizes) {
		perror("Image header too small\n");
		return EFI_UNSUPPORTED;
	}

	HeaderWithoutDataDir = OptHeaderSize
			- sizeof (EFI_IMAGE_DATA_DIRECTORY) * EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES;
	if (((UINT32)PEHdr->Pe32.FileHeader.SizeOfOptionalHeader - HeaderWithoutDataDir) !=
			context->NumberOfRvaAndSizes * sizeof (EFI_IMAGE_DATA_DIRECTORY)) {
		perror("Image header overflows data directory\n");
		return EFI_UNSUPPORTED;
	}

	SectionHeaderOffset = DosHdr->e_lfanew
				+ sizeof (UINT32)
				+ sizeof (EFI_IMAGE_FILE_HEADER)
				+ PEHdr->Pe32.FileHeader.SizeOfOptionalHeader;
	if (((UINT32)context->ImageSize - SectionHeaderOffset) / EFI_IMAGE_SIZEOF_SECTION_HEADER
			<= context->NumberOfSections) {
		perror("Image sections overflow image size\n");
		return EFI_UNSUPPORTED;
	}

	if ((context->SizeOfHeaders - SectionHeaderOffset) / EFI_IMAGE_SIZEOF_SECTION_HEADER
			< (UINT32)context->NumberOfSections) {
		perror("Image sections overflow section headers\n");
		return EFI_UNSUPPORTED;
	}

	if ((((UINT8 *)PEHdr - (UINT8 *)data) + sizeof(EFI_IMAGE_OPTIONAL_HEADER_UNION)) > datasize) {
		perror("Invalid image\n");
		return EFI_UNSUPPORTED;
	}

	if (PEHdr->Te.Signature != EFI_IMAGE_NT_SIGNATURE) {
		perror("Unsupported image type\n");
		return EFI_UNSUPPORTED;
	}

	if (PEHdr->Pe32.FileHeader.Characteristics & EFI_IMAGE_FILE_RELOCS_STRIPPED) {
		perror("Unsupported image - Relocations have been stripped\n");
		return EFI_UNSUPPORTED;
	}

	context->PEHdr = PEHdr;

	if (image_is_64_bit(PEHdr)) {
		context->ImageAddress = PEHdr->Pe32Plus.OptionalHeader.ImageBase;
		context->EntryPoint = PEHdr->Pe32Plus.OptionalHeader.AddressOfEntryPoint;
		context->RelocDir = &PEHdr->Pe32Plus.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC];
		context->SecDir = &PEHdr->Pe32Plus.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY];
	} else {
		context->ImageAddress = PEHdr->Pe32.OptionalHeader.ImageBase;
		context->EntryPoint = PEHdr->Pe32.OptionalHeader.AddressOfEntryPoint;
		context->RelocDir = &PEHdr->Pe32.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC];
		context->SecDir = &PEHdr->Pe32.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY];
	}

	context->FirstSection = (EFI_IMAGE_SECTION_HEADER *)((char *)PEHdr + PEHdr->Pe32.FileHeader.SizeOfOptionalHeader + sizeof(UINT32) + sizeof(EFI_IMAGE_FILE_HEADER));

	if (context->ImageSize < context->SizeOfHeaders) {
		perror("Invalid image\n");
		return EFI_UNSUPPORTED;
	}

	if ((unsigned long)((UINT8 *)context->SecDir - (UINT8 *)data) >
	    (datasize - sizeof(EFI_IMAGE_DATA_DIRECTORY))) {
		perror("Invalid image\n");
		return EFI_UNSUPPORTED;
	}

	if (context->SecDir->VirtualAddress > datasize ||
	    (context->SecDir->VirtualAddress == datasize &&
	     context->SecDir->Size > 0)) {
		perror("Malformed security header\n");
		return EFI_INVALID_PARAMETER;
	}
	return EFI_SUCCESS;
}

#define check_size_line(data, datasize_in, hashbase, hashsize, l) ({	\
	if ((unsigned long)hashbase >					\
			(unsigned long)data + datasize_in) {		\
		efi_status = EFI_INVALID_PARAMETER;			\
		perror("%s:%d Invalid hash base 0x%016lx\n", __FILE__, l,\
			(unsigned long)hashbase);			\
		goto done;						\
	}								\
	if ((unsigned long)hashbase + hashsize >			\
			(unsigned long)data + datasize_in) {		\
		efi_status = EFI_INVALID_PARAMETER;			\
		perror("%s:%d Invalid hash size 0x%016lx\n", __FILE__, l,\
			(unsigned long)hashsize);			\
		goto done;						\
	}								\
})
#define check_size(d, ds, h, hs) check_size_line(d, ds, h, hs, __LINE__)

EFI_STATUS
get_section_vma (UINTN section_num,
		 char *buffer, size_t bufsz UNUSED,
		 PE_COFF_LOADER_IMAGE_CONTEXT *context,
		 char **basep, size_t *sizep,
		 EFI_IMAGE_SECTION_HEADER **sectionp)
{
	EFI_IMAGE_SECTION_HEADER *sections = context->FirstSection;
	EFI_IMAGE_SECTION_HEADER *section;
	char *base = NULL, *end = NULL;

	if (section_num >= context->NumberOfSections)
		return EFI_NOT_FOUND;

	if (context->FirstSection == NULL) {
		perror("Invalid section %lu requested\n", section_num);
		return EFI_UNSUPPORTED;
	}

	section = &sections[section_num];

	base = ImageAddress (buffer, context->ImageSize, section->VirtualAddress);
	end = ImageAddress (buffer, context->ImageSize,
			    section->VirtualAddress + section->Misc.VirtualSize - 1);

	if (!(section->Characteristics & EFI_IMAGE_SCN_MEM_DISCARDABLE)) {
		if (!base) {
			perror("Section %lu has invalid base address\n", section_num);
			return EFI_UNSUPPORTED;
		}
		if (!end) {
			perror("Section %lu has zero size\n", section_num);
			return EFI_UNSUPPORTED;
		}
	}

	if (!(section->Characteristics & EFI_IMAGE_SCN_CNT_UNINITIALIZED_DATA) &&
	    (section->VirtualAddress < context->SizeOfHeaders ||
	     section->PointerToRawData < context->SizeOfHeaders)) {
		perror("Section %lu is inside image headers\n", section_num);
		return EFI_UNSUPPORTED;
	}

	if (end < base) {
		perror("Section %lu has negative size\n", section_num);
		return EFI_UNSUPPORTED;
	}

	*basep = base;
	*sizep = end - base;
	*sectionp = section;
	return EFI_SUCCESS;
}

EFI_STATUS
generate_hash(char *data, unsigned int datasize_in,
	      PE_COFF_LOADER_IMAGE_CONTEXT *context, UINT8 *sha256hash, UINT8 *sha1hash UNUSED)
{
	unsigned int sha256ctxsize;
	unsigned int size = datasize_in;
	void *sha256ctx = NULL;
	char *hashbase;
	unsigned int hashsize;
	unsigned int SumOfBytesHashed, SumOfSectionBytes;
	unsigned int index, pos;
	unsigned int datasize;
	EFI_IMAGE_SECTION_HEADER *Section;
	EFI_IMAGE_SECTION_HEADER *SectionHeader = NULL;
	EFI_STATUS efi_status = EFI_SUCCESS;
	EFI_IMAGE_DOS_HEADER *DosHdr = (void *)data;
	unsigned int PEHdr_offset = 0;

	size = datasize = datasize_in;

	if (datasize <= sizeof (*DosHdr) ||
	    DosHdr->e_magic != EFI_IMAGE_DOS_SIGNATURE) {
		perror("Invalid signature\n");
		return EFI_INVALID_PARAMETER;
	}
	PEHdr_offset = DosHdr->e_lfanew;

	sha256ctxsize = Sha256GetContextSize();
	sha256ctx = AllocatePool(sha256ctxsize);

	if (!sha256ctx) {
		perror("Unable to allocate memory for hash context\n");
		return EFI_OUT_OF_RESOURCES;
	}

	if (!Sha256Init(sha256ctx)) {
		perror("Unable to initialise hash\n");
		efi_status = EFI_OUT_OF_RESOURCES;
		goto done;
	}

	/* Hash start to checksum */
	hashbase = data;
	hashsize = (char *)&context->PEHdr->Pe32.OptionalHeader.CheckSum -
		hashbase;
	check_size(data, datasize_in, hashbase, hashsize);

	printf("%s:%s:%d: digesting %lx + %lx\n", __FILE__, __func__, __LINE__,
	       (unsigned long)hashbase - (unsigned long)data, (unsigned long)hashsize);
	if (!(Sha256Update(sha256ctx, hashbase, hashsize))) {
		perror("Unable to generate hash\n");
		efi_status = EFI_OUT_OF_RESOURCES;
		goto done;
	}

	/* Hash post-checksum to start of certificate table */
	hashbase = (char *)&context->PEHdr->Pe32.OptionalHeader.CheckSum +
		sizeof (int);
	hashsize = (char *)context->SecDir - hashbase;
	check_size(data, datasize_in, hashbase, hashsize);

	printf("%s:%s:%d: digesting %lx + %lx\n", __FILE__, __func__, __LINE__,
	       (unsigned long)hashbase - (unsigned long)data, (unsigned long)hashsize);
	if (!(Sha256Update(sha256ctx, hashbase, hashsize))) {
		perror("Unable to generate hash\n");
		efi_status = EFI_OUT_OF_RESOURCES;
		goto done;
	}

	/* Hash end of certificate table to end of image header */
	EFI_IMAGE_DATA_DIRECTORY *dd = context->SecDir + 1;
	hashbase = (char *)dd;
	hashsize = context->SizeOfHeaders - (unsigned long)((char *)dd - data);
	if (hashsize > datasize_in) {
		perror("Data Directory size %u is invalid\n", hashsize);
		efi_status = EFI_INVALID_PARAMETER;
		goto done;
	}
	check_size(data, datasize_in, hashbase, hashsize);

	printf("%s:%s:%d: digesting %lx + %lx\n", __FILE__, __func__, __LINE__,
	       (unsigned long)hashbase - (unsigned long)data, (unsigned long)hashsize);
	if (!(Sha256Update(sha256ctx, hashbase, hashsize))) {
		perror("Unable to generate hash\n");
		efi_status = EFI_OUT_OF_RESOURCES;
		goto done;
	}

	/* Sort sections */
	SumOfBytesHashed = context->SizeOfHeaders;

	/*
	 * XXX Do we need this here, or is it already done in all cases?
	 */
	if (context->NumberOfSections == 0 ||
	    context->FirstSection == NULL) {
		uint16_t opthdrsz;
		uint64_t addr;
		uint16_t nsections;
		EFI_IMAGE_SECTION_HEADER *section0, *sectionN;

		nsections = context->PEHdr->Pe32.FileHeader.NumberOfSections;
		opthdrsz = context->PEHdr->Pe32.FileHeader.SizeOfOptionalHeader;

		/* Validate section0 is within image */
		addr = PEHdr_offset + sizeof(UINT32)
			+ sizeof(EFI_IMAGE_FILE_HEADER)
			+ opthdrsz;
		section0 = ImageAddress(data, datasize, addr);
		if (!section0) {
			perror("Malformed file header.\n");
			perror("Image address for Section Header 0 is 0x%016lx\n",
			       addr);
			perror("File size is 0x%016lx\n", (unsigned long)datasize);
			efi_status = EFI_INVALID_PARAMETER;
			goto done;
		}

		/* Validate sectionN is within image */
		addr += (uint64_t)(intptr_t)&section0[nsections-1] -
			(uint64_t)(intptr_t)section0;
		sectionN = ImageAddress(data, datasize, addr);
		if (!sectionN) {
			perror("Malformed file header.\n");
			perror("Image address for Section Header %d is 0x%016lx\n",
			       nsections - 1, addr);
			perror("File size is 0x%016lx\n", (unsigned long)datasize);
			efi_status = EFI_INVALID_PARAMETER;
			goto done;
		}

		context->NumberOfSections = nsections;
		context->FirstSection = section0;
	}

	/*
	 * Allocate a new section table so we can sort them without
	 * modifying the image.
	 */
	SectionHeader = AllocateZeroPool (sizeof (EFI_IMAGE_SECTION_HEADER)
					  * context->NumberOfSections);
	if (SectionHeader == NULL) {
		perror("Unable to allocate section header\n");
		efi_status = EFI_OUT_OF_RESOURCES;
		goto done;
	}

	/*
	 * Validate section locations and sizes, and sort the table into
	 * our newly allocated header table
	 */
	SumOfSectionBytes = 0;
	Section = context->FirstSection;
	for (index = 0; index < context->NumberOfSections; index++) {
		EFI_IMAGE_SECTION_HEADER *SectionPtr;
		char *base;
		size_t size;

		efi_status = get_section_vma(index, data, datasize, context,
					     &base, &size, &SectionPtr);
		if (efi_status == EFI_NOT_FOUND)
			break;
		if (EFI_ERROR(efi_status)) {
			perror("Malformed section header\n");
			goto done;
		}

		/* Validate section size is within image. */
		if (SectionPtr->SizeOfRawData >
		    datasize - SumOfBytesHashed - SumOfSectionBytes) {
			perror("Malformed section %d size\n", index);
			efi_status = EFI_INVALID_PARAMETER;
			goto done;
		}
		SumOfSectionBytes += SectionPtr->SizeOfRawData;

		pos = index;
		while ((pos > 0) && (Section->PointerToRawData < SectionHeader[pos - 1].PointerToRawData)) {
			CopyMem (&SectionHeader[pos], &SectionHeader[pos - 1], sizeof (EFI_IMAGE_SECTION_HEADER));
			pos--;
		}
		CopyMem (&SectionHeader[pos], Section, sizeof (EFI_IMAGE_SECTION_HEADER));
		Section += 1;

	}

	/* Hash the sections */
	for (index = 0; index < context->NumberOfSections; index++) {
		Section = &SectionHeader[index];
		if (Section->SizeOfRawData == 0) {
			continue;
		}

		hashbase  = ImageAddress(data, size, Section->PointerToRawData);
		if (!hashbase) {
			perror("Malformed section header\n");
			efi_status = EFI_INVALID_PARAMETER;
			goto done;
		}

		/* Verify hashsize within image. */
		if (Section->SizeOfRawData >
		    datasize - Section->PointerToRawData) {
			perror("Malformed section raw size %d\n", index);
			efi_status = EFI_INVALID_PARAMETER;
			goto done;
		}
		hashsize  = (unsigned int) Section->SizeOfRawData;
		check_size(data, datasize_in, hashbase, hashsize);

		printf("%s:%s:%d: digesting %lx + %lx\n", __FILE__, __func__, __LINE__,
		       (unsigned long)hashbase - (unsigned long)data, (unsigned long)hashsize);
		if (!(Sha256Update(sha256ctx, hashbase, hashsize))) {
			perror("Unable to generate hash\n");
			efi_status = EFI_OUT_OF_RESOURCES;
			goto done;
		}
		SumOfBytesHashed += Section->SizeOfRawData;
	}

	/* Hash all remaining data up to SecDir if SecDir->Size is not 0 */
	if (datasize > SumOfBytesHashed && context->SecDir->Size) {
		hashbase = data + SumOfBytesHashed;
		hashsize = datasize - context->SecDir->Size - SumOfBytesHashed;

		if ((datasize - SumOfBytesHashed < context->SecDir->Size) ||
		    (SumOfBytesHashed + hashsize != context->SecDir->VirtualAddress)) {
			perror("Malformed binary after Attribute Certificate Table\n");
			printf("datasize: %u SumOfBytesHashed: %u SecDir->Size: %u\n",
				      datasize, SumOfBytesHashed, context->SecDir->Size);
			printf("hashsize: %u SecDir->VirtualAddress: 0x%08x\n",
				      hashsize, context->SecDir->VirtualAddress);
			efi_status = EFI_INVALID_PARAMETER;
			goto done;
		}
		check_size(data, datasize_in, hashbase, hashsize);

		printf("%s:%s:%d: digesting %lx + %lx\n", __FILE__, __func__, __LINE__,
		       (unsigned long)hashbase - (unsigned long)data, (unsigned long)hashsize);
		if (!(Sha256Update(sha256ctx, hashbase, hashsize))) {
			perror("Unable to generate hash\n");
			efi_status = EFI_OUT_OF_RESOURCES;
			goto done;
		}

#if 1
	}
#else // we have to migrate to doing this later :/
		SumOfBytesHashed += hashsize;
	}

	/* Hash all remaining data */
	if (datasize > SumOfBytesHashed) {
		hashbase = data + SumOfBytesHashed;
		hashsize = datasize - SumOfBytesHashed;

		check_size(data, datasize_in, hashbase, hashsize);

		printf("%s:%s:%d: digesting %lx + %lx\n", __FILE__, __func__, __LINE__,
		       (unsigned long)hashbase - (unsigned long)data, (unsigned long)hashsize);
		if (!(Sha256Update(sha256ctx, hashbase, hashsize))) {
			perror("Unable to generate hash\n");
			efi_status = EFI_OUT_OF_RESOURCES;
			goto done;
		}

		SumOfBytesHashed += hashsize;
	}
#endif

	if (!(Sha256Final(sha256ctx, sha256hash))) {
		perror("Unable to finalise hash\n");
		efi_status = EFI_OUT_OF_RESOURCES;
		goto done;
	}

	dprint("sha256 authenticode hash:");
	int i;
	for (i = 0; i < SHA256_DIGEST_SIZE; i++)
		printf("%02hhx ", sha256hash[i]);
	printf("\n");

done:
	if (SectionHeader)
		FreePool(SectionHeader);
	if (sha256ctx)
		FreePool(sha256ctx);

	return efi_status;
}




static void
usage(int status)
{
	FILE *out = status == 0 ? stdout : stderr;
	fprintf(out,
		"Usage: %s [OPTION...] -i FILE\n"
		"  -i, --infile=<file>		input binary\n"
		"  -q, --quiet			be quieter\n"
		"  -v, --verbose		be louder\n",
		program_invocation_short_name);
	exit(status);
}

int
main(int argc, char *argv[]) {
	char *infile = NULL;
	const char sopts[] = ":i:v?";
	struct option lopts[] = {
		{"infile", required_argument, NULL, 'i' },
		{"quiet", no_argument, NULL, 'q' },
		{"verbose", no_argument, NULL, 'v' },
                {"usage", no_argument, NULL, '?' },
                {"help", no_argument, NULL, '?' },
                {NULL, 0, NULL, '\0' }
        };
	int rc;
	int c;
	int i = 0;
	int verbose = 1;
	PE_COFF_LOADER_IMAGE_CONTEXT ctx;
	uint8_t sha256hash[32];
	FILE *in;
	void *data = NULL;
	unsigned int datasz = 0;
	struct stat statbuf;
	size_t rsz, tsz = 0;
	EFI_STATUS efi_status;

	opterr = 0;
	while ((c = getopt_long(argc, argv, sopts, lopts, &i)) != -1) {
		switch (c) {
		case 'i':
			if (optarg == NULL)
				errx(1, "No input file specified\n");
			infile = optarg;
			break;
		case 'q':
			verbose -= 1;
			break;
		case 'v':
			verbose += 1;
			break;
		case '?':
			usage(0);
			break;
		case ':':
			if (optarg == NULL)
				break;
			warnx("option '%c' does not take an argument (\"%s\")",
			      optopt, optarg);
			usage(1);
			break;
		}
	}

	if (infile == NULL) {
		warnx("No input file provided");
		usage(1);
	}

	in = fopen(infile, "r");
	if (!in)
		err(1, "Could not open \"%s\"", infile);

	rc = fstat(fileno(in), &statbuf);
	if (rc < 0)
		err(1, "Could not stat \"%s\"", infile);

	datasz = statbuf.st_size;
	data = calloc(1, datasz+1);
	if (!data)
		err(1, "Could not allocated %u bytes", datasz);

	do {
		rsz = fread(data, 1, datasz - tsz, in);
		if (rsz == 0) {
			if (ferror(in))
				err(1, "Could not read from \"%s\"", infile);
			if (feof(in))
				break;
		}
		tsz += rsz;
	} while (tsz < datasz);
	fclose(in);

	efi_status = read_header(data, datasz, &ctx);
	if (EFI_ERROR(efi_status))
		errx(1, "Could not parse PE header for \"%s\"", infile);

	efi_status = generate_hash(data, datasz, &ctx, sha256hash, NULL);
	if (EFI_ERROR(efi_status))
		errx(1, "Could not hash PE binary \"%s\"", infile);

	return 0;
}

// vim:fenc=utf-8:tw=75:noet
