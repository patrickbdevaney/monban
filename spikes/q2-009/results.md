| run | conns | idle RSS | peak RSS | peak ΔRSS / conn | max buffered / conn (exact) | reaped | live streams @5/12/20 s |
|---|---:|---:|---:|---:|---:|---:|---|
| h2-baseline · bigwin-noread | 1 | 3.3 MiB | 44.2 MiB | 40.91 MiB | 39.06 MiB | 0 | 100/100/100 |
| h2-baseline · bigwin-noread | 10 | 3.3 MiB | 405.9 MiB | 40.27 MiB | 39.07 MiB | 0 | 1000/1000/1000 |
| h2-baseline · bigwin-noread (wave2) | 100 | 3.3 MiB | 5603.6 MiB | 56.0 MiB | 39.08 MiB | 0 | 10000/10000/- |
| h2-baseline · bigwin-noread | 100 | 3.3 MiB | 4015.6 MiB | 40.12 MiB | 39.08 MiB | 0 | 10000/10000/10000 |
| h2-baseline · continuation | 10 | 3.3 MiB | 4.1 MiB | 0.08 MiB | 0.0 MiB | 0 | 0/-/- |
| h2-baseline · rapidreset (burst1000) | 1 | 3.3 MiB | 3.7 MiB | 0.41 MiB | 0.0 MiB | 0 | 0/-/- |
| h2-baseline · rapidreset | 10 | 3.3 MiB | 4.0 MiB | 0.07 MiB | 0.0 MiB | 0 | 0/-/- |
| h2-baseline · slowread | 10 | 3.3 MiB | 406.1 MiB | 40.28 MiB | 39.07 MiB | 0 | 1000/1000/1000 |
| h2-baseline · window0 | 1 | 3.4 MiB | 3.8 MiB | 0.42 MiB | 0.0 MiB | 0 | 100/100/100 |
| h2-baseline · window0 | 10 | 3.4 MiB | 5.3 MiB | 0.19 MiB | 0.0 MiB | 0 | 1000/1000/1000 |
| h2-baseline · window0 | 100 | 3.3 MiB | 20.1 MiB | 0.17 MiB | 0.0 MiB | 0 | 10000/10000/10000 |
| h2-wrapper · bigwin-noread | 1 | 3.4 MiB | 16.6 MiB | 13.21 MiB | 12.05 MiB | 100 | 100/0/0 |
| h2-wrapper · bigwin-noread (long) | 10 | 3.4 MiB | 130.9 MiB | 12.75 MiB | 12.05 MiB | 1000 | 1000/0/0 |
| h2-wrapper · bigwin-noread | 10 | 3.3 MiB | 130.6 MiB | 12.73 MiB | 12.04 MiB | 1000 | 1000/0/0 |
| h2-wrapper · bigwin-noread (wave2) | 100 | 3.4 MiB | 1298.7 MiB | 12.95 MiB | 12.05 MiB | 20000 | 10000/9448/10000 |
| h2-wrapper · bigwin-noread | 100 | 3.3 MiB | 1255.9 MiB | 12.53 MiB | 12.05 MiB | 10000 | 10000/0/0 |
| h2-wrapper · continuation | 10 | 3.3 MiB | 4.1 MiB | 0.07 MiB | 0.0 MiB | 0 | 0/-/- |
| h2-wrapper · rapidreset (burst1000) | 1 | 3.2 MiB | 3.6 MiB | 0.42 MiB | 0.0 MiB | 0 | 0/-/- |
| h2-wrapper · rapidreset | 10 | 3.3 MiB | 3.9 MiB | 0.06 MiB | 0.0 MiB | 0 | 0/-/- |
| h2-wrapper · slowread | 10 | 3.3 MiB | 130.8 MiB | 12.74 MiB | 12.03 MiB | 1000 | 1000/0/0 |
| h2-wrapper · window0 | 1 | 3.3 MiB | 3.7 MiB | 0.44 MiB | 0.0 MiB | 100 | 100/0/0 |
| h2-wrapper · window0 | 10 | 3.4 MiB | 5.5 MiB | 0.21 MiB | 0.0 MiB | 1000 | 1000/0/0 |
| h2-wrapper · window0 | 100 | 3.4 MiB | 20.8 MiB | 0.17 MiB | 0.0 MiB | 10000 | 10000/0/0 |
| hyper-baseline · bigwin-noread | 1 | 3.3 MiB | 45.7 MiB | 42.38 MiB | 40.64 MiB | 0 | 100/100/100 |
| hyper-baseline · bigwin-noread | 10 | 3.3 MiB | 420.6 MiB | 41.72 MiB | 40.64 MiB | 0 | 1000/1000/1000 |
| hyper-baseline · bigwin-noread | 100 | 3.3 MiB | 4175.8 MiB | 41.72 MiB | 40.64 MiB | 0 | 10000/10000/10000 |
| hyper-baseline · continuation | 10 | 3.3 MiB | 4.1 MiB | 0.08 MiB | 0.0 MiB | 0 | 0/-/- |
| hyper-baseline · rapidreset (burst1000) | 1 | 3.3 MiB | 3.7 MiB | 0.35 MiB | 0.0 MiB | 0 | 0/-/- |
| hyper-baseline · rapidreset | 10 | 3.4 MiB | 4.1 MiB | 0.07 MiB | 0.0 MiB | 0 | 0/-/- |
| hyper-baseline · slowread | 10 | 3.4 MiB | 421.8 MiB | 41.84 MiB | 40.64 MiB | 0 | 1000/1000/1000 |
| hyper-baseline · window0 | 1 | 3.4 MiB | 5.4 MiB | 2.02 MiB | 1.56 MiB | 0 | 100/100/100 |
| hyper-baseline · window0 | 10 | 3.2 MiB | 20.8 MiB | 1.77 MiB | 1.56 MiB | 0 | 1000/1000/1000 |
| hyper-baseline · window0 | 100 | 3.3 MiB | 174.6 MiB | 1.71 MiB | 1.56 MiB | 0 | 10000/10000/10000 |

RSS curve (MiB, seconds since server start; attack starts at ~1 s, client holds until ~26 s):

| run | conns | 2s | 5s | 9s | 12s | 15s | 20s | 26s | 30s | 40s | 50s |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| h2-baseline · bigwin-noread | 1 | 44.2 | 44.2 | 44.2 | 44.2 | 44.2 | 44.2 | 44.2 | 9.1 |  |  |
| h2-baseline · bigwin-noread | 10 | 405.9 | 405.9 | 405.9 | 405.9 | 405.9 | 405.9 | 405.9 | 67.0 |  |  |
| h2-baseline · bigwin-noread (wave2) | 100 | 4014.5 | 4014.5 | 4014.5 | 4014.5 |  |  |  |  |  |  |
| h2-baseline · bigwin-noread | 100 | 4015.6 | 4015.6 | 4015.6 | 4015.6 | 4015.6 | 4015.6 | 4015.6 | 2770.7 |  |  |
| h2-baseline · slowread | 10 | 406.0 | 406.0 | 406.0 | 406.0 | 406.0 | 406.0 | 406.1 | 151.7 |  |  |
| h2-baseline · window0 | 1 | 3.8 | 3.8 | 3.8 | 3.8 | 3.8 | 3.8 | 3.8 | 3.8 |  |  |
| h2-baseline · window0 | 10 | 5.3 | 5.3 | 5.3 | 5.3 | 5.3 | 5.3 | 5.3 | 5.3 |  |  |
| h2-baseline · window0 | 100 | 20.1 | 20.1 | 20.1 | 20.1 | 20.1 | 20.1 | 20.1 | 19.4 |  |  |
| h2-wrapper · bigwin-noread | 1 | 16.6 | 16.6 | 16.6 | 8.7 | 8.7 | 8.7 | 8.7 | 7.9 |  |  |
| h2-wrapper · bigwin-noread (long) | 10 | 130.9 | 130.9 | 130.8 | 100.8 | 100.8 | 100.8 | 100.8 | 100.8 | 19.7 | 19.7 |
| h2-wrapper · bigwin-noread | 10 | 130.6 | 130.6 | 130.6 | 71.7 | 71.7 | 71.7 | 71.7 | 30.0 |  |  |
| h2-wrapper · bigwin-noread (wave2) | 100 | 1258.6 | 1258.6 | 1258.6 | 1213.9 | 1298.7 | 1298.7 | 1245.8 |  |  |  |
| h2-wrapper · bigwin-noread | 100 | 1255.9 | 1255.9 | 1255.9 | 1208.6 | 1208.6 | 1208.6 | 1208.6 | 581.4 |  |  |
| h2-wrapper · slowread | 10 | 130.8 | 130.8 | 130.8 | 73.4 | 73.4 | 73.4 | 73.4 | 18.8 |  |  |
| h2-wrapper · window0 | 1 | 3.7 | 3.7 | 3.7 | 3.7 | 3.7 | 3.7 | 3.7 | 3.7 |  |  |
| h2-wrapper · window0 | 10 | 5.3 | 5.3 | 5.3 | 5.5 | 5.5 | 5.5 | 5.5 | 5.1 |  |  |
| h2-wrapper · window0 | 100 | 20.5 | 20.5 | 20.5 | 20.8 | 20.8 | 20.8 | 20.8 | 20.4 |  |  |
| hyper-baseline · bigwin-noread | 1 | 45.7 | 45.7 | 45.7 | 45.7 | 45.7 | 45.7 | 45.7 | 22.3 |  |  |
| hyper-baseline · bigwin-noread | 10 | 420.6 | 420.6 | 420.6 | 420.6 | 420.6 | 420.6 | 420.6 | 196.7 |  |  |
| hyper-baseline · bigwin-noread | 100 | 4175.8 | 4175.8 | 4175.8 | 4175.8 | 4175.8 | 4175.8 | 4175.8 | 3432.6 |  |  |
| hyper-baseline · slowread | 10 | 421.8 | 421.8 | 421.8 | 421.8 | 421.8 | 421.8 | 421.8 | 306.9 |  |  |
| hyper-baseline · window0 | 1 | 5.4 | 5.4 | 5.4 | 5.4 | 5.4 | 5.4 | 5.4 | 4.9 |  |  |
| hyper-baseline · window0 | 10 | 20.8 | 20.8 | 20.8 | 20.8 | 20.8 | 20.8 | 20.8 | 9.4 |  |  |
| hyper-baseline · window0 | 100 | 174.6 | 174.6 | 174.6 | 174.6 | 174.6 | 174.6 | 174.6 | 86.6 |  |  |
