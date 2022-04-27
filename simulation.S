#ifdef SIMULATE_ENABLED_STATE
.balign 1, 0

.global simulated_pk
.type simulated_pk, %object
.size simulated_pk, simulated_pk_end - simulated_pk
.section .rodata, "a", %progbits
simulated_pk:
.incbin SIMULATED_PK
simulated_pk_end:
.balign 4, 0
.global simulated_pk_size
.type simulated_pk_size, %object
.size simulated_pk_size, 4
.section .rodata, "a", %progbits
simulated_pk_size:
.4byte simulated_pk_end - simulated_pk

.global simulated_kek
.type simulated_kek, %object
.size simulated_kek, simulated_kek_end - simulated_kek
.section .rodata, "a", %progbits
simulated_kek:
.incbin SIMULATED_KEK
simulated_kek_end:
.balign 4, 0
.global simulated_kek_size
.type simulated_kek_size, %object
.size simulated_kek_size, 4
.section .rodata, "a", %progbits
simulated_kek_size:
.4byte simulated_kek_end - simulated_kek

.global simulated_db
.type simulated_db, %object
.size simulated_db, simulated_db_end - simulated_db
.section .rodata, "a", %progbits
simulated_db:
.incbin SIMULATED_DB
simulated_db_end:
.global simulated_db_size
.type simulated_db_size, %object
.size simulated_db_size, 4
.section .rodata, "a", %progbits
.balign 4, 0
simulated_db_size:
.4byte simulated_db_end - simulated_db

.global simulated_dbx
.type simulated_dbx, %object
.size simulated_dbx, simulated_dbx_end - simulated_dbx
.section .rodata, "a", %progbits
simulated_dbx:
.incbin SIMULATED_DBX
simulated_dbx_end:
.global simulated_dbx_size
.type simulated_dbx_size, %object
.size simulated_dbx_size, 4
.section .rodata, "a", %progbits
.balign 4, 0
simulated_dbx_size:
.4byte simulated_dbx_end - simulated_dbx

.global simulated_secureboot
.type simulated_secureboot, %object
.size simulated_secureboot, simulated_secureboot_end - simulated_secureboot
.section .rodata, "a", %progbits
simulated_secureboot:
.incbin SIMULATED_SECUREBOOT
simulated_secureboot_end:
.global simulated_secureboot_size
.type simulated_secureboot_size, %object
.size simulated_secureboot_size, 4
.section .rodata, "a", %progbits
.balign 4, 0
simulated_secureboot_size:
.4byte simulated_secureboot_end - simulated_secureboot

.global simulated_setupmode
.type simulated_setupmode, %object
.size simulated_setupmode, simulated_setupmode_end - simulated_setupmode
.section .rodata, "a", %progbits
simulated_setupmode:
.incbin SIMULATED_SETUPMODE
simulated_setupmode_end:
.global simulated_setupmode_size
.type simulated_setupmode_size, %object
.size simulated_setupmode_size, 4
.section .rodata, "a", %progbits
.balign 4, 0
simulated_setupmode_size:
.4byte simulated_setupmode_end - simulated_setupmode

#endif /* SIMULATE_ENABLED_STATE */
