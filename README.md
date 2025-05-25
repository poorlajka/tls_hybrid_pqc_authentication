## Current folder structure

mbedtls contains the original library code + the combiner.
The combiner contains it's implementation + the nist signature schemes.

## Dependencies

* make 
* cmake 
* meson 
* ninja-build 
* openssl 
* libgmp3-dev

## TODO list
- [x] Clean up stdout (dbg + prints) 
- [x] Fix nesting bug introduced by flattening keys 
- [ ] Fix client side certificate authentication callback
- [ ] Fix measurments for handshake 
- [ ] Add website for transfer with information about handshake 

## Benchmark spitball

Split the benchmark up into two parts:

* An initial benchmark only using the combiner covering all relevant scheme combinations. Based on the results of this benchmark elect a number of candidates for further testing in the tls handshake.

Look for balanced hybrid candidates by something like this maby 
~~~

from dataclasses import dataclass

@dataclass
class Hybrid:
    name: str
    sig_cycles: int
    ver_cycles: int
    pk_size: int
    sig_size: int

def hspeed(h):
    return h.sign_cycles + h.ver_cycles

def hsize(h):
    return h.pk_size + h.sig_size

def find_candidates(nr_of_candidates)
    hybrids = []
    with open("benchmark_results.txt", "r") as benchmarks
        for benchmark in benchmarks:
            name, sig_cycles, ver_cycles, pk_size, sig_size = benchmark.split(" ")
            hybrids.append(Hybrid(name, sig_cycles, ver_cycles, pk_size, sig_size))

    speed_mean = sum(map(hspeed, hybrids))/len(hybrids)
    speed_std_deviation = sum(map(lambda h : (hspeed(h) - speed_mean), hybrids))
    speed_deviations = map(lambda h : (h, (speed(h) - speed_mean)/speed_std_deviation))

    size_mean = sum(map(hsize, hybrids))/len(hybrids)
    size_std_deviation = sum(map(lambda h : (hsize(h) - size_mean), hybrids))
    size_deviations = map(lambda h : (h, (speed(h) - speed_mean)/speed_std_deviation))

    total_deviations = map(lambda d1, d2 : (d1[0], d1[1] + d2[1]), zip(speed_deviations, size_deviations))

    candidates = sorted(key = lambda d : d[1], total_deviations)[:nr_of_candidates]

~~~
    