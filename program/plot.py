import matplotlib.pyplot as plt
import numpy as np


x = np.loadtxt('side_channel_info/table.out')

plt.plot(x)
plt.ylabel('Y value')
plt.xlabel('X value')
plt.title('title')

plt.show()

