from matplotlib import pyplot as plt


def graph1(r, t):
    r.sort()
    ys = []

    i = 0
    for x in range(1600):
        while i < len(r) and r[i] < x:
            i += 1
        ys.append(float(i) / float(t))

    plt.plot(list(map(lambda ri: float(ri) / 1, range(1600))), ys, label="Simulation")
    plt.xlim(0)
    plt.ylim(0)
    plt.xlabel("Number of faulty signatures q")
    plt.ylabel("Success probability")
    plt.legend(loc="lower right")
    plt.grid()
    plt.show()


def graph2(r, t):
    for f in r:
        r[f].sort()
        ys = []

        i = 0
        for x in range(400):
            while i < len(r[f]) and r[f][i] < x:
                i += 1
            ys.append(float(i) / float(t[f]))

        plt.plot(list(map(lambda ri: float(ri) / 1, range(400))), ys, label=f)
    plt.xlim(0)
    plt.ylim(0)
    plt.xlabel("Number of forgery attempts p")
    plt.ylabel("Success probability")
    plt.legend(loc="lower right", title="q")
    plt.grid()
    plt.show()


try:
    readings = []
    total = 0

    with open("singleAttackStats.csv", "r") as results:
        for line in results:
            reading = int(line.strip())
            total += 1
            if reading != -1:
                readings.append(reading)

    graph1(readings, total)
except IOError as e:
    print("Error reading results 1")
    print(e)

try:
    readings = {}
    totals = {}

    with open("parallelAttackStats.csv", "r") as results:
        for line in results:
            faults, reading = list(map(int, line.strip().split(",")))
            if faults not in readings:
                readings[faults] = []
                totals[faults] = 0
            totals[faults] += 1
            if reading != -1:
                readings[faults].append(reading)

    graph2(readings, totals)
except IOError as e:
    print("Error reading results 2")
    print(e)
