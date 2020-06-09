import matplotlib.pyplot as plt
import numpy as np


x, y = np.loadtxt('diff_score.out', delimiter=',', unpack=True)

plt.plot(x,y)
plt.ylabel('Y value')
plt.xlabel('X value')
plt.title('title')

plt.show()
