| php_version | arch | distro | image | stage1 | stage2 | zif_system | zval_ptr_dtor | htdata | heap_leak | libphp_leak | rce | status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 8.0.30 | amd64 | bullseye | php:8.0.30-apache | - | - | 0x3495d0 | 0x4319a0 | - | no | no | no | calibration failed before complete ASLR disclosure |
| 8.1.34 | amd64 | trixie | php:8.1.34-apache | - | - | 0x36f470 | 0x457150 | - | no | no | no | calibration failed before complete ASLR disclosure |
| 8.2.34 | amd64 | trixie | php:8.2.34-apache | - | - | 0x39b8a0 | 0x487650 | - | no | no | no | calibration failed before complete ASLR disclosure |
| 8.3.35 | aarch64 | trixie | php:8.3.35-apache | 841/63 | 406/16 | 0x377428 | 0x46fcc0 | - | yes | yes | no | leaks calibrated; stage 3 not verified |
| 8.3.35 | amd64 | trixie | php:8.3.35-apache | 841/63 | 406/16 | 0x3ac080 | 0x49ec50 | - | yes | yes | no | leaks calibrated; stage 3 not verified |
| 8.4.25 | aarch64 | trixie | php:8.4.25-apache | 841/63 | 406/16 | 0x42fa30 | 0x637ae0 | 0x690d8 | yes | yes | yes | RCE verified with runtime ASLR bases |
| 8.4.26 | amd64 | trixie | php:8.4.26-apache | 841/79 | 406/16 | 0x465370 | 0x65eb60 | 0x690d8 | yes | yes | yes | RCE verified with runtime ASLR bases |
| 8.5.0 | aarch64 | trixie | php:8.5.0-apache | 841/63 | 406/16 | 0x503510 | 0x731d80 | - | yes | yes | no | leaks calibrated; stage 3 not verified |
| 8.5.10 | aarch64 | trixie | php:8.5.10-apache | 841/63 | 406/16 | 0x52e130 | 0x75d360 | 0x690d8 | yes | yes | yes | RCE verified with runtime ASLR bases |
| 8.5.11 | aarch64 | trixie | php:8.5.11-apache | 841/63 | 406/16 | 0x5314f0 | 0x761b80 | 0x690d8 | yes | yes | yes | RCE verified with runtime ASLR bases |
| 8.5.11 | amd64 | trixie | php:8.5.11-apache | 841/63 | 406/16 | 0x5996e0 | 0x7b47a0 | 0x690d8 | yes | yes | yes | RCE verified with runtime ASLR bases |

Profiles: **11**; verified RCE: **5**.
