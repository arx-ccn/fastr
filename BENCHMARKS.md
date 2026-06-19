
## 2026-06-12 00:46 UTC - x86_64 8cpu 8192MB

> events=50000  queries=5000  concurrency=8

| Metric                              | fastr              | strfry             | rnostr             | winner   |
|-------------------------------------|--------------------|--------------------|--------------------|----------|
| Ingest throughput (ev/s)            | 126908        | 2779        | 599928        | rnostr  |
| Ingest OK p50 latency (µs)          | 54      | 2549      | 12      | rnostr |
| Ingest OK p99 latency (µs)          | 92      | 6819      | 18      | rnostr |
| Ingest errors                       | 0        | 0        | 50000        | tie  |
| Neg-sync wall time (ms)             | 34        | 32        | n/a               | strfry  |
| REQ query throughput (q/s)          | 54390        | 4131        | 214270        | rnostr  |
| REQ->EOSE p50 latency (µs)           | 123      | 1860      | 29      | rnostr |
| REQ->EOSE p99 latency (µs)           | 187      | 2606      | 54      | rnostr |
| Peak RSS @ 50000 events (MB)    | 23       | 73       | 11       | rnostr |
| Disk usage @ 50000 events (MB)  | 11        | 53        | 0        | fastr  |
| Disk I/O written (MB)               | 11        | 5647        | 0        | fastr  |
| CPU Mcycles (user)                  | 10477        | 25740        | 1108        | rnostr  |
| CPU Mcycles (kernel)                | 2112        | 56548        | 831        | rnostr  |
| Syscalls                            | 377256        | 6302837        | 210879        | rnostr  |
| Context switches                    | 111013        | 1378746        | 65724        | rnostr |
| Minor page faults                   | 5246        | 10712        | 237        | rnostr  |
| Open file descriptors (peak)        | 9        | 21        | 47        | fastr  |
| Cold start time (µs)                | 1346 | 23128 | 124597 | fastr |


## 2026-06-12 00:49 UTC - x86_64 8cpu 8192MB

> events=500000  queries=50000  concurrency=8

| Metric                              | fastr              | strfry             | rnostr             | winner   |
|-------------------------------------|--------------------|--------------------|--------------------|----------|
| Ingest throughput (ev/s)            | 136426        | 2143        | 728192        | rnostr  |
| Ingest OK p50 latency (µs)          | 52      | 3262      | 10      | rnostr |
| Ingest OK p99 latency (µs)          | 88      | 14565      | 15      | rnostr |
| Ingest errors                       | 0        | 0        | 500000        | tie  |
| Neg-sync wall time (ms)             | 405        | 317        | n/a               | strfry  |
| REQ query throughput (q/s)          | 34162        | 6105        | 99567        | rnostr  |
| REQ->EOSE p50 latency (µs)           | 193      | 1216      | 32      | rnostr |
| REQ->EOSE p99 latency (µs)           | 372      | 2288      | 58      | rnostr |
| Peak RSS @ 500000 events (MB)    | 127       | 556       | 11       | rnostr |
| Disk usage @ 500000 events (MB)  | 119        | 526        | 0        | fastr  |
| Disk I/O written (MB)               | 119        | 79001        | 0        | fastr  |
| CPU Mcycles (user)                  | 117923        | 266479        | 10822        | rnostr  |
| CPU Mcycles (kernel)                | 21335        | 790217        | 8254        | rnostr  |
| Syscalls                            | 3800724        | 77194035        | 2112249        | rnostr  |
| Context switches                    | 1151108        | 17721870        | 655881        | rnostr |
| Minor page faults                   | 13293        | 84299        | 438        | rnostr  |
| Open file descriptors (peak)        | 9        | 21        | 47        | fastr  |
| Cold start time (µs)                | 1436 | 49880 | 25005 | fastr |


## 2026-06-12 01:10 UTC - x86_64 8cpu 8192MB

> events=50000  queries=5000  concurrency=8

| Metric                              | fastr              | strfry             | rnostr             | winner   |
|-------------------------------------|--------------------|--------------------|--------------------|----------|
| Ingest throughput (ev/s)            | 129333        | 2509        | 0        | fastr  |
| Ingest OK p50 latency (µs)          | 56      | 2950      | 0      | fastr |
| Ingest OK p99 latency (µs)          | 131      | 7057      | 0      | fastr |
| Ingest errors                       | 0        | 0        | 0        | tie  |
| Neg-sync wall time (ms)             | 33        | 30        | n/a               | strfry  |
| REQ query throughput (q/s)          | 52379        | 5495        | 195        | fastr  |
| REQ->EOSE p50 latency (µs)           | 142      | 1309      | 41028      | fastr |
| REQ->EOSE p99 latency (µs)           | 242      | 2485      | 42048      | fastr |
| Peak RSS @ 50000 events (MB)    | 23       | 72       | 25       | fastr |
| Disk usage @ 50000 events (MB)  | 11        | 53        | 10        | rnostr  |
| Disk I/O written (MB)               | 11        | 5889        | 498        | fastr  |
| CPU Mcycles (user)                  | 11951        | 27398        | 11499        | rnostr  |
| CPU Mcycles (kernel)                | 2388        | 61338        | 9755        | fastr  |
| Syscalls                            | 378824        | 6266304        | 891393        | fastr  |
| Context switches                    | 115448        | 1467986        | 205340        | fastr |
| Minor page faults                   | 5235        | 10126        | 2090        | rnostr  |
| Open file descriptors (peak)        | 9        | 21        | 47        | fastr  |
| Cold start time (µs)                | 1157 | 23219 | 35489 | fastr |


## 2026-06-12 01:09 UTC - x86_64 8cpu 8192MB

> events=500000  queries=50000  concurrency=8

| Metric                              | fastr              | strfry             | rnostr             | winner   |
|-------------------------------------|--------------------|--------------------|--------------------|----------|
| Ingest throughput (ev/s)            | 144290        | 2275        | 0        | fastr  |
| Ingest OK p50 latency (µs)          | 50      | 3278      | 0      | fastr |
| Ingest OK p99 latency (µs)          | 84      | 8860      | 0      | fastr |
| Ingest errors                       | 0        | 0        | 0        | tie  |
| Neg-sync wall time (ms)             | 397        | 302        | n/a               | strfry  |
| REQ query throughput (q/s)          | 62405        | 6308        | 0        | fastr  |
| REQ->EOSE p50 latency (µs)           | 117      | 1190      | 0      | fastr |
| REQ->EOSE p99 latency (µs)           | 169      | 2206      | 0      | fastr |
| Peak RSS @ 500000 events (MB)    | 126       | 556       | 26       | rnostr |
| Disk usage @ 500000 events (MB)  | 119        | 526        | 10        | rnostr  |
| Disk I/O written (MB)               | 119        | 89455        | 501        | fastr  |
| CPU Mcycles (user)                  | 110358        | 267257        | 36022        | rnostr  |
| CPU Mcycles (kernel)                | 20434        | 820560        | 18078        | rnostr  |
| Syscalls                            | 3759489        | 76607594        | 3613230        | rnostr  |
| Context switches                    | 1107914        | 17653532        | 727780        | rnostr |
| Minor page faults                   | 12797        | 83712        | 2342        | rnostr  |
| Open file descriptors (peak)        | 9        | 21        | 47        | fastr  |
| Cold start time (µs)                | 1231 | 34125 | 90949 | fastr |


## 2026-06-12 01:14 UTC - x86_64 8cpu 8192MB

> events=500000  queries=50000  concurrency=8

| Metric                              | fastr              | strfry             | rnostr             | winner   |
|-------------------------------------|--------------------|--------------------|--------------------|----------|
| Ingest throughput (ev/s)            | 136163        | 2092        | 0        | fastr  |
| Ingest OK p50 latency (µs)          | 53      | 3512      | 0      | fastr |
| Ingest OK p99 latency (µs)          | 91      | 12815      | 0      | fastr |
| Ingest errors                       | 0        | 0        | 0        | tie  |
| Neg-sync wall time (ms)             | 387        | 301        | n/a               | strfry  |
| REQ query throughput (q/s)          | 64662        | 6399        | 0        | fastr  |
| REQ->EOSE p50 latency (µs)           | 115      | 1165      | 0      | fastr |
| REQ->EOSE p99 latency (µs)           | 175      | 2255      | 0      | fastr |
| Peak RSS @ 500000 events (MB)    | 125       | 557       | 26       | rnostr |
| Disk usage @ 500000 events (MB)  | 119        | 526        | 10        | rnostr  |
| Disk I/O written (MB)               | 119        | 90579        | 556        | fastr  |
| CPU Mcycles (user)                  | 110656        | 270859        | 27559        | rnostr  |
| CPU Mcycles (kernel)                | 20988        | 849237        | 15232        | rnostr  |
| Syscalls                            | 3760467        | 77821155        | 3390762        | rnostr  |
| Context switches                    | 1110718        | 17990720        | 600220        | rnostr |
| Minor page faults                   | 13030        | 83258        | 2328        | rnostr  |
| Open file descriptors (peak)        | 9        | 21        | 47        | fastr  |
| Cold start time (µs)                | 1253 | 23540 | 23985 | fastr |


## 2026-06-12 01:27 UTC - x86_64 8cpu 8192MB

> events=500000  queries=50000  concurrency=8

| Metric                              | fastr              | strfry             | rnostr             | winner   |
|-------------------------------------|--------------------|--------------------|--------------------|----------|
| Ingest throughput (ev/s)            | 138716        | 2283        | 80        | fastr  |
| Ingest OK p50 latency (µs)          | 52      | 3343      | 99998      | fastr |
| Ingest OK p99 latency (µs)          | 87      | 7187      | 103289      | fastr |
| Ingest errors                       | 0        | 0        | 0        | tie  |
| Neg-sync wall time (ms)             | 400        | 302        | n/a               | strfry  |
| REQ query throughput (q/s)          | 67471        | 6268        | 202        | fastr  |
| REQ->EOSE p50 latency (µs)           | 109      | 1204      | 41014      | fastr |
| REQ->EOSE p99 latency (µs)           | 156      | 2143      | 42043      | fastr |
| Peak RSS @ 500000 events (MB)    | 125       | 557       | 535       | fastr |
| Disk usage @ 500000 events (KB)  | 122450        | 539024        | 541234        | fastr  |
| Disk I/O written (MB)               | 119        | 90143        | 52581        | fastr  |
| CPU Mcycles (user)                  | 109018        | 269466        | 339346        | fastr  |
| CPU Mcycles (kernel)                | 20570        | 836350        | 641389        | fastr  |
| Syscalls                            | 3760857        | 77245436        | 18757983        | fastr  |
| Context switches                    | 1109332        | 17733586        | 4728160        | fastr |
| Minor page faults                   | 12793        | 84288        | 57658        | fastr  |
| Open file descriptors (peak)        | 9        | 21        | 47        | fastr  |
| Cold start time (µs)                | 1595 | 35334 | 91152 | fastr |

