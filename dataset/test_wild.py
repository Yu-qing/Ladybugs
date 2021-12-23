import csv
import os
import time

start = time.time()

path = 'smartbugs_wild_2000.csv'
with open(path, newline='') as csvfile:
    rows = csv.reader(csvfile, delimiter=',')
    
    for row in rows:
        os.system("slither {0}".format(row[0]))

end = time.time()
print("spend time : ", end-start, "(s)")
