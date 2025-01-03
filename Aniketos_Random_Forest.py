import pandas as pd
import chardet # is used to auto detect what encoding a file has so no more encoding errors YAY! (hopefully)
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.ensemble import RandomForestClassifier

from sklearn.model_selection import train_test_split # mports train , test split function 
from sklearn import metrics # imports scikit-learn metrics module for accuracy calculation 
from sklearn.metrics import accuracy_score # this allows us to get an accuracy score


def predictingMalware(model):

    file_path = 'File_DATA_TEST.csv'

    # this auto detects the encoding ype of the file and assigns it to the variable encoding ready to use in the read file argument
    with open(file_path, "rb") as f: 
        result = chardet.detect(f.read())
        encoding = result['encoding']

    new_df = pd.read_csv(file_path, encoding=encoding)

    # Specify the columns you want to read
    columns_to_read = ['filesize', 'entropy']

    x = new_df[columns_to_read] #features

    predictions = model.predict(x)
    new_df['Predicted Result'] = predictions
    new_df.to_csv(file_path, index=False)



file_path = 'Malware dataset\Malware and Benign dataset.csv'

# this auto detects the encoding ype of the file and assigns it to the variable encoding ready to use in the read file argument
with open(file_path, "rb") as f: 
    result = chardet.detect(f.read())
    encoding = result['encoding']

df = pd.read_csv(file_path, encoding=encoding)

# Specify the columns you want to read
columns_to_read = ['filesize', 'entropy']

x = df[columns_to_read] #features
y = df['Label']

x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=1)  

# instantiate model
rf = RandomForestClassifier()

# fit the model 
rf.fit(x_train, y_train)

# get a prediction
y_predlr = rf.predict(x_test)

# Accuracy score using sklearn metrics lib
print('Accuracy: ' , accuracy_score(y_test, y_predlr))


predictingMalware(rf)


actual = y_test
predicted = y_predlr
#creates confusion matrix
confusion_matrix = metrics.confusion_matrix(actual, predicted)

#displays the confusion matrix as a 4x4 grid
cm_display = metrics.ConfusionMatrixDisplay(confusion_matrix = confusion_matrix, display_labels = ['Malware', 'Benign'])

#produces a the confusion matrix in a graphical format
cm_display.plot()
plt.show()