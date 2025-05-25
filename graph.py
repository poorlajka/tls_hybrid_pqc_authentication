import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
import matplotlib
import random
import textwrap
from adjustText import adjust_text

# Input directoreis
RUNTIME_DATA_DIR = "./runtime_data"
CERT_SIZE_DATA_DIR = "./cert_size_data"
# Output directory
GRAPH_DIR = "./graphs2" 

def set_pgf():
    matplotlib.use("pgf")
    matplotlib.rcParams.update({
        "pgf.texsystem": "pdflatex",
        'font.family': 'serif',
        'text.usetex': True,
        'pgf.rcfonts': False,
    })

def gen_box_diagrams(savefig):

    for nist_cat in ["cat1", "cat3", "cat5"]:

        len1_runtimes, len2_runtimes, len3_runtimes = [], [], []
        for combiner in ["CONCATENATION", "STRONG_NESTING"]:

            with open("./runtime_data/{}_size1_{}.txt".format(combiner, nist_cat), "r") as file:
                len1_runtimes += [x for x in [float(line.split(" ")[2]) 
                                      for line in file.readlines()] if x < 50000]

            with open("./runtime_data/{}_size2_{}.txt".format(combiner, nist_cat), "r") as file:
                len2_runtimes += [x for x in [float(line.split(" ")[3]) 
                                      for line in file.readlines()] if x < 50000]

            with open("./runtime_data/{}_size3_{}.txt".format(combiner, nist_cat), "r") as file:
                len3_runtimes += [x for x in [float(line.split(" ")[4]) 
                                      for line in file.readlines()] if x < 50000] 

        plt.boxplot(
            [len1_runtimes, len2_runtimes, len3_runtimes], 
            vert=True, 
            patch_artist=True, 
            showfliers=True, 
            boxprops=dict(facecolor="skyblue")
        )
        plt.xlabel("Hybrid length")
        plt.ylabel("Runtime [ms]")

        if savefig:
            plt.savefig("{}/boxplot_{}.pgf".format(GRAPH_DIR, nist_cat))
        else:
            plt.show()

        plt.cla()
        plt.clf()

def gen_top_hybrids(savefig):
    for nist_cat in ["cat1", "cat3", "cat5"]:
        for hybrid_len in [2, 3]:

            nesting_runtimes, nesting_hybrids, nesting_sizes = [], [], []
            with open("./runtime_data/{}_size{}_{}.txt"
                      .format("STRONG_NESTING", hybrid_len, nist_cat), "r") as file:
                lines = file.readlines()

                nesting_runtimes = [float(line.split(" ")[hybrid_len+1]) 
                                    for line in lines]

                nesting_hybrids = [" ".join(line.split(" ")[1:hybrid_len+1]).strip(":") 
                                   for line in lines]

            with open("./cert_size_data/{}_size{}_{}.txt"
                      .format("STRONG_NESTING", hybrid_len, nist_cat), "r") as file:

                nesting_sizes = [float(line.split(" ")[hybrid_len+1]) 
                                 for line in file.readlines()]


            concat_runtimes, concat_hybrids, concat_sizes = [], [], []
            with open("./runtime_data/{}_size{}_{}.txt"
                      .format("CONCATENATION", hybrid_len, nist_cat), "r") as file:
                lines = file.readlines()

                concat_runtimes = [float(line.split(" ")[hybrid_len+1]) 
                                   for line in lines]
                concat_hybrids = [" ".join(line.split(" ")[1:hybrid_len+1]).strip(":") 
                                  for line in lines]

            with open("./cert_size_data/{}_size{}_{}.txt"
                      .format("CONCATENATION", hybrid_len, nist_cat), "r") as file:

                concat_sizes = [float(line.split(" ")[hybrid_len+1]) 
                                for line in file.readlines()]

            for size_constraint in [64e3, 32e3, 16e3]:

                nesting_data = []
                for hybrid, runtime, size in zip(nesting_hybrids, nesting_runtimes, nesting_sizes):
                    if size < size_constraint:
                        nesting_data.append((hybrid, runtime))
                
                n_hybrids, n_runtimes = zip(*sorted(nesting_data, key=lambda x: x[1])[:20])

                concat_data = []
                for hybrid, runtime, size in zip(concat_hybrids, concat_runtimes, concat_sizes):
                    if size < size_constraint:
                        concat_data.append((hybrid, runtime))
                
                c_hybrids, c_runtimes = zip(*sorted(concat_data, key=lambda x: x[1])[:20])

                plt.subplots(layout="constrained")

                color1 = "#1f77b4"
                color2 = "#ff7f0e"
                plt.barh(
                    n_hybrids, 
                    n_runtimes, 
                    color='#1f77b4', alpha=0.7,
                    label="Strong nesting", 
                )

                plt.barh(
                    c_hybrids, 
                    c_runtimes, 
                    label="Concatenation", 
                    color='#ff7f0e', alpha=0.7,
                )

                plt.ylabel("Hybrid")
                plt.xlabel("Runtime [ms]")
                plt.grid(True, linewidth=0.3)
                plt.gca().set_axisbelow(True)
                patch1 = mpatches.Patch(color=color1, label='Strong nesting')
                patch2 = mpatches.Patch(color=color2, label='Concatenation')
                plt.legend(handles=[patch1, patch2], loc='upper center', bbox_to_anchor=(0.5, -0.1),
                fancybox=True, shadow=False, ncol=2)
                if savefig:
                    plt.savefig("{}/top_bar{}_{}_{}.pgf".format(GRAPH_DIR, hybrid_len, nist_cat, size_constraint))
                else:
                    plt.show()
                plt.cla()
                plt.clf()
                plt.close('all')

def sort_sizes(sizes, times):
    order = [(size, get_pos(size, times)) for size in sizes]
    return [o[0] for o in sorted(order, key=lambda x: x[1])]

def get_pos(size, times):
    size_schemes = size.split(":")[0].split(".")[1].strip()
    for time in times:
        time_schemes = time.split(":")[0].split(".")[1].strip()
        time_pos = int(time.split(":")[0].split(".")[0])
        if size_schemes == time_schemes:
            return time_pos

def gen_scatter_plots(individual, savefig):
    lens = []
    if individual:
        lens = [1]
    else:
        lens = [2, 3]

    for nist_cat in ["cat1", "cat3", "cat5"]:
        for hybrid_len in lens:
            times = []
            sizes = []
            times_lines = []
            names=[]
            with open("./runtime_data/{}_size{}_{}.txt".format("STRONG_NESTING", hybrid_len, nist_cat), "r") as file:
                times_lines = file.readlines()
                times = [float(line.split(" ")[hybrid_len+1]) for line in times_lines]
                names = [line.split(" ")[1].strip(":") for line in times_lines]

            with open("./cert_size_data/{}_size{}_{}.txt".format("STRONG_NESTING", hybrid_len, nist_cat), "r") as file:
                lines = sort_sizes(file.readlines(), times_lines)
                """
                for line in lines[:10]:
                    print(line)
                """
                sizes = [float(line.split(" ")[hybrid_len+1]) for line in lines]
            
            ctimes = []
            csizes = []
            ctimes_lines = []
            cnames=[]
            if not individual:
                with open("./runtime_data/{}_size{}_{}.txt".format("CONCATENATION", hybrid_len, nist_cat), "r") as file:
                    ctimes_lines = file.readlines()
                    ctimes = [float(line.split(" ")[hybrid_len+1]) for line in ctimes_lines]
                    cnames = [line.split(" ")[1].strip(":") for line in ctimes_lines]

                with open("./cert_size_data/{}_size{}_{}.txt".format("CONCATENATION", hybrid_len, nist_cat), "r") as file:
                    lines = sort_sizes(file.readlines(), ctimes_lines)
                    """
                    for line in lines[:10]:
                        print(line)
                    """
                    csizes = [float(line.split(" ")[hybrid_len+1]) for line in lines]
            


            plt.subplots(layout="constrained")
            times = list(filter(lambda x: x < 20000, times))
            sizes = sizes[:len(times)]
            if not individual:
                ctimes = list(filter(lambda x: x < 20000, ctimes))
                csizes = csizes[:len(ctimes)]


            if individual:
                names[names.index("SPHINCS")] = "SPHINCS+"
                ed25519_index = names.index("ED25519")
                colors = ["#1f77b4"] * (len(names) - 1)
                colors[ed25519_index] = "#ff7f0e"
                offsets = [(5, -5), (-5, 5)]  * 17
                offsets[names.index("FALCON")] = (-15, -10)
                offsets[names.index("SPHINCS+")] = (-15, -10)
                min_len = min(len(times), len(sizes), len(colors))
                times, sizes, colors = times[:min_len], sizes[:min_len], colors[:min_len]

                plt.scatter(times, sizes, c=colors)

                for xi, yi, label, offset in zip(times, sizes, names, offsets):
                    plt.annotate(label,
                                    xy=(xi, yi),
                                    xytext=offset,
                                    textcoords='offset points', fontsize=6)
            else:
                plt.scatter(times, sizes, color="#1f77b4", alpha=0.7, label="Strong nesting")
                plt.scatter(ctimes, csizes, color="#ff7f0e", alpha=0.7, label="Concatenation")

                patch1 = mpatches.Patch(color="#1f77b4", label='Strong nesting')
                patch2 = mpatches.Patch(color="#ff7f0e", label='Concatenation')
                plt.legend(handles=[patch1, patch2], loc='upper center', bbox_to_anchor=(0.5, -0.1),
                fancybox=True, shadow=False, ncol=2)

            texts = []
            horizontal_align = ['left', 'left', 'left', 'left', 'left'] * 5
            vertical_align = ['center'] * 17

            plt.ylabel("Certificate size [B]")
            plt.xlabel("Runtime [ms]")

            plt.grid(True, linewidth=0.3)
            plt.gca().set_axisbelow(True)
            plt.xscale("log")
            plt.yscale("log")

            if savefig:
                plt.savefig("{}/scatter{}_{}.pgf".format(GRAPH_DIR, hybrid_len, nist_cat))
            else:
                plt.show()
            plt.cla()
            plt.clf()
            plt.close('all')

"""
import pandas as pd

def gen_scheme_table():
    hybrid_len = 1
    nist_cat = "cat5"
    with open("./runtime_data/{}_size{}_{}.txt".format("STRONG_NESTING", hybrid_len, nist_cat), "r") as file:
        times_lines = file.readlines()
        data = [round(float(line.split(" ")[hybrid_len+1])) for line in times_lines]
        hybrid = [" ".join(line.split(" ")[1:hybrid_len+1]).strip(":") for line in times_lines]

    with open("./cert_size_data/{}_size{}_{}.txt".format("STRONG_NESTING", hybrid_len, nist_cat), "r") as file:
        lines = sort_sizes(file.readlines(), times_lines)
        sizes = [float(line.split(" ")[hybrid_len+1]) for line in lines]

        df = pd.DataFrame({
            "Scheme": hybrid[:-1],
            "Runtime [ms]": data[:-1],
            "Certificate size [B]": sizes[:-1]
        })

        latex_code = df.to_latex(
            index=False, 
            caption="Scheme performances", 
            label="tab:scheme_performance", 
            float_format=lambda x: f"{x:.4g}",
            longtable=True
        )
        print(latex_code)
        print("\\Floatbarrier")

gen_scheme_table()
"""

def gen_all_graphs():
    savefig = False
    if savefig:
        set_pgf()
    gen_box_diagrams(savefig=savefig)
    #gen_bar_charts()
    #gen_top_hybrids(savefig=savefig)
    gen_scatter_plots(individual=True, savefig=savefig)
    #gen_scatter_plots(individual=False, savefig=savefig)

gen_all_graphs()

