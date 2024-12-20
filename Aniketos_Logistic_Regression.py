import pandas as pd
import chardet # is used to auto detect what encoding a file has so no more encoding errors YAY! (hopefully)
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.linear_model import LogisticRegression # logistic regression model
from sklearn.model_selection import train_test_split # mports train , test split function 
from sklearn import metrics # imports scikit-learn metrics module for accuracy calculation 
from sklearn.metrics import accuracy_score # this allows us to get an accuracy score


# PREPROCESSING

file_path = 'Malware dataset\Malware dataset.csv'

# this auto detects the encoding ype of the file and assigns it to the variable encoding ready to use in the read file argument
with open(file_path, "rb") as f: 
    result = chardet.detect(f.read())
    encoding = result['encoding']


df = pd.read_csv(file_path, encoding=encoding)

label_array = []

classy = df['classification']

for row in classy:
    if row == 'malware':
        label_array.append('1') # 1 == malware to be true 
    elif row == 'benign':
        label_array.append('0')  # 0 == malware to be false

df['Label'] = label_array
df.to_csv(file_path, index=False)

# ANALYSIS

# Specify the columns you want to read
columns_to_read = ["millisecond","state", "usage_counter", "prio", "static_prio", "normal_prio", "policy", "vm_pgoff", "vm_truncate_count", "task_size", "cached_hole_size", "free_area_cache", "mm_users", "map_count", "hiwater_rss", "total_vm", "shared_vm", "exec_vm", "reserved_vm", "nr_ptes", "end_data","last_interval", "nvcsw", "nivcsw", "min_flt", "maj_flt", "fs_excl_counter", "lock", "utime", "stime", "gtime", "cgtime", "signal_nvcsw"]

x = df[columns_to_read] #features
y = df['Label']

x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=1)  

# instantiate model
lr = LogisticRegression(max_iter=10000)

# fit the model 
lr.fit(x_train, y_train)

# get a prediction
y_predlr = lr.predict(x_test)

actual = y_test
predicted = y_predlr

# Accuracy score using sklearn metrics lib
print('Accuracy: ' , accuracy_score(y_test, y_predlr))

#creates confusion matrix
confusion_matrix = metrics.confusion_matrix(actual, predicted)

#displays the confusion matrix as a 4x4 grid
cm_display = metrics.ConfusionMatrixDisplay(confusion_matrix = confusion_matrix, display_labels = ['Malware', 'Benign'])

#produces a the confusion matrix in a graphical format
cm_display.plot()
plt.show()