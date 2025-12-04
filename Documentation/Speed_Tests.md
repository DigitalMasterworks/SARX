[sarx_bench_core] pure keystream: data=1024 MB, threads=12
elapsed = 0.099 s, throughput = 10346.92 MB/s (pure keystream)

[sarx_bench_core] pure keystream: data=1024 MB, threads=12
elapsed = 0.092 s, throughput = 11081.00 MB/s (pure keystream)

[sarx_bench_core] pure keystream: data=1024 MB, threads=12
elapsed = 0.093 s, throughput = 11013.18 MB/s (pure keystream)

[sarx_bench_core] pure keystream: data=1024 MB, threads=12

with aead:

[sarx_bench_stream] Parallel stream: 12 HW threads, data=100 MB
THREADS	KS(MB/s)	ENC(MB/s)	DEC(MB/s)	Roundtrip(ms)	OK
1	1451.18		847.76		986.61		219.315		YES
2	1728.37		1498.47		1699.82		125.565		YES
4	3465.68		2148.20		2087.27		94.460		YES
6	4631.66		2776.97		2115.61		83.278		YES
8	5416.93		3129.83		2178.79		77.848		YES
12	7348.16		3690.45		2234.96		71.841		YES

[sarx_bench_stream] Parallel stream: 12 HW threads, data=100 MB
THREADS	KS(MB/s)	ENC(MB/s)	DEC(MB/s)	Roundtrip(ms)	OK
1	1469.36		844.80		989.90		219.392		YES
2	1794.54		1490.85		1976.54		117.669		YES
4	3032.97		2272.45		2071.31		92.284		YES
6	4689.37		2522.53		2096.73		87.336		YES
8	5357.83		3157.96		2024.05		81.072		YES
12	7256.07		3581.32		2187.38		73.640		YES

