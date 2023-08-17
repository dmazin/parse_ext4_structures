How to prepare the bitmap directory for `parse`:
1. `sudo bpftrace trace.bt` while `dd`ing into /dev/sdd1.
2. Copy/paste the (10) traces into traces.txt.
3. `sudo python read_locations_from_traces_into_dir.py traces.txt /dev/sdd`: note that we specify disk not partition
4. `sudo ./parse bitmap-dump-2023-08-17-16 /dev/sdd1`

by the way here's how i compiled parse: `gcc parse.c hexdump.c -o parse -lext2fs -Wall -Wextra -pedantic`

note that the C code is probably horrendous to anyone who is good at C. sorry!
