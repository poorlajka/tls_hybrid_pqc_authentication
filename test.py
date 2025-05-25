import subprocess
import time
from itertools import product, combinations
from pathlib import Path
# need jsonschema to build

HANDSHAKE_ITERATIONS = 5
MBEDTLS_BUILD = "./mbedtls/build_dir2"
HANDSHAKE_FAIL_VAL = 10e9

SCHEMES = [
    [
        "CROSS",
        "LESS",
    ],
    [
        "MAYO",
        "QRUOV",
        #"UOV",
        "SNOVA",
    ],
    [
        "RYDE", 
        "PERK", 
        "MIRATH", 
        "MQOM", 
        "SDITH", 
    ],
    [
        "HAWK", 
        "FALCON", 
        "DILITHIUM",
    ],
    [
        "SPHINCS", 
        "FAEST", 
    ],
    [
        "SQISIGN", 
    ],
    [ 
        "ED25519", 
    ],
]

def configure_network(throughput: int, packet_loss: float, delay: int) -> None:
    subprocess.run(
        ['''tc qdisc add dev lo root handle 1: htb default 12 && 
         tc class add dev lo parent 1: classid 1:12 htb rate {}mbit &&
         tc qdisc add dev lo parent 1:12 handle 120: netem loss {}%% delay {}ms'''
         .format(throughput, packet_loss, delay)], 
        shell=True,
        capture_output=True,
    )

def kill_server() -> None:
    subprocess.run(
        ["kill $(lsof -t -i:4433)"],
        shell=True, 
        capture_output=True,
    )

def compile_mbedtls(nist_cat: int) -> None:
    subprocess.run(
        [
            "cd {} && cmake -S .. -DCMAKE_BUILD_TYPE=RELEASE -DNIST_SEC_CAT={} .. && cmake -S .."
            .format(MBEDTLS_BUILD, nist_cat)
        ], 
        shell=True, 
        capture_output=True,
    )
    subprocess.run(
        ["cd {} && cmake --build .".format(MBEDTLS_BUILD)], 
        shell=True, 
        capture_output=True,
    )

def run_tls_handshake(combiner: str, schemes: list[str]) -> tuple[int, int]:
    hybrid_len = len(schemes)
    schemes_str = ",".join(schemes)

    """
        Generate keypair 
    """
    result = subprocess.run(
        [
            '''cd {} && 
            prlimit --stack=unlimited --pid $$; ulimit -s unlimited && 
            ./combiner/combiner_keygen combiner={} hybrid_len={} schemes={}'''
            .format(MBEDTLS_BUILD, combiner, hybrid_len, schemes_str)
        ], 
        shell=True,
        capture_output=True,
    )

    """
        Create hybrid certificate 
    """
    subprocess.run(
        [
            '''cd {} && 
            prlimit --stack=unlimited --pid $$; ulimit -s unlimited && 
            ./programs/x509/cert_write_hybrid issuer_key=hybrid_keypair.key output_file=hybrid_crt.crt'''
            .format(MBEDTLS_BUILD),
        ],
        shell=True, 
        capture_output=True,
    )

    benchmark_file_name = "{}/hybrid_benchmark_{}_{}".format(
        MBEDTLS_BUILD, 
        combiner, "_".join(schemes),
    )
    """
        Delete old benchmark data
    """
    with open(benchmark_file_name, "w") as file:
        pass
    
    for _ in range(HANDSHAKE_ITERATIONS):
        """
            Start TLS server 
        """
        kill_server()
        server_proc = subprocess.Popen(
            [
                '''cd {} && 
                prlimit --stack=unlimited --pid $$; ulimit -s unlimited && 
                ./programs/ssl/ssl_server'''
                .format(MBEDTLS_BUILD),
            ],
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        time.sleep(0.2) # Make sure the server has started before starting the client

        """
            Start TLS client 
        """
        subprocess.run(
            ['''
                cd {} && 
                prlimit --stack=unlimited --pid $$; ulimit -s unlimited && 
                ./programs/ssl/ssl_client1'''
                .format(MBEDTLS_BUILD),
            ],
            shell=True, 
            capture_output=True,
        )
        server_proc.terminate()
        kill_server()
        
    hybrid_cert_path = Path("{}/hybrid_crt.crt".format(MBEDTLS_BUILD))
    hybrid_cert_size = hybrid_cert_path.stat().st_size

    with open(benchmark_file_name, "r+") as file:
        times = [float(line) for line in file.readlines()]

        if len(times):
            return (round(10e2 * sum(times)/len(times)), hybrid_cert_size)
        else:
            return (HANDSHAKE_FAIL_VAL, hybrid_cert_size)

def main() -> None:
    #configure_network(throughput=1, packet_loss=50, delay=100)
    for nist_cat in [3, 5]:
        print("Compiling Mbed TLS for NIST security category {}".format(nist_cat))
        compile_mbedtls(nist_cat)

        for combiner in ["CONCATENATION", "STRONG_NESTING"]:
            for hybrid_len in [1, 2, 3]:
                schemes = SCHEMES if hybrid_len == 1 else SCHEMES[:-1]
                family_combinations = combinations(schemes, hybrid_len)

                hybrid_combinations = []
                for c in family_combinations:
                    hybrid_combinations.extend(product(*c))

                print("Running {} {} hybrids of length {}".format(len(hybrid_combinations), combiner, hybrid_len))

                hybrid_benchmark = [(hybrid, run_tls_handshake(combiner, hybrid))
                            for hybrid in hybrid_combinations]
                
                hybrid_runtimes, hybrid_cert_sizes = zip(
                    *[((hybrid, runtime), (hybrid, cert_size)) 
                      for hybrid, (runtime, cert_size) 
                      in sorted(hybrid_benchmark, key=lambda x: x[1][0])]
                )

                with open(
                    "./runtime_data/{}_size{}_cat{}.txt"
                    .format(str(combiner), hybrid_len, nist_cat), "w",
                ) as file:

                    for i, (hybrid, runtime) in enumerate(hybrid_runtimes):
                        file.write(
                            "{}. {}: {} ms\n"
                            .format(i+1, ", ".join(hybrid), runtime)
                        )

                with open(
                    "./cert_size_data/{}_size{}_cat{}.txt"
                    .format(str(combiner), hybrid_len, nist_cat), "w",
                ) as file:
                    for i, (hybrid, cert_size) in enumerate(hybrid_cert_sizes):
                        file.write(
                            "{}. {}: {} bytes\n"
                            .format(i+1, ", ".join(hybrid), cert_size)
                        )


if __name__ == "__main__":
    main()