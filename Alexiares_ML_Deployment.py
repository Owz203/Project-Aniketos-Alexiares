'''
====================================Libs===================================
'''
import os
import math

import csv #used to write to csv docs
import pandas as pd
import chardet # is used to auto detect what encoding a file

from sklearn.ensemble import RandomForestClassifier

from sklearn.model_selection import train_test_split # imports train , test split function 
from sklearn.metrics import accuracy_score # this allows for accuracy score


'''
====================================SCAN FILES===================================
'''

def scanFiles(dir):

    file_data = []

    for root,_, files in os.walk(dir):
        for file in files: 
            file_path = os.path.join(root,file)

            # Feature extraction
            # file_sig = getFileSignature(file_path)
            file_size = getFileSize(file_path)
            file_entropy = getFileEntropy(file_path)

            # Puts all data into array
            file_data.append(file_path)
            # file_data.append(file_sig)
            file_data.append(file_size)
            file_data.append(file_entropy)
    
    return file_data




'''
====================================Feature Extraction===================================
'''


'''
File Extension (HEX) (Not in use)
'''
# # this extracts the hex values from a file to derive the file extension
# def getFileSignature(file):
    
#     with open(file, "rb") as f:
#         # Read the first 4 bytes of the file
#         first_bytes = f.read(4)

#         # Convert the bytes to hex values
#         hex_values = first_bytes.hex()

#         return hex_values

#         # Print the first 4 hex values
#         # print(hex_values[:8]) 
#         # print(hex_values)

'''
File Size (bytes)
'''
# Get file size
def getFileSize(file):

    file_size = os.path.getsize(file)

    return file_size

'''
File Entropy
'''
# This calculates the entropy of a file

def getFileEntropy(file):

    with open(file, 'rb') as f:
        byte_array = f.read()

    file_size = len(byte_array)
    if file_size == 0:
        return 0.0

    freq_list = [0] * 256
    for byte in byte_array:
        freq_list[byte] += 1

    entropy = 0.0
    for freq in freq_list:
        if freq > 0:
            probability = float(freq) / file_size
            entropy -= probability * math.log2(probability)

    return entropy


'''
====================================Make CSV=============================================
'''

def createCSV(data):

    headers = ['filename', 'filesize', 'entropy'] # column titles to be added to csv

    # Makes new csv in directory 
    with open('File_DATA.csv', 'w', newline='') as file:

        writer = csv.writer(file)# give the ability to insert data into a csv

        writer.writerow(headers) # adds column titles at the top
        
        # loops through python list to insert 4 values of list into one row at a time
        for i in range(0, len(data), 3):
            writer.writerow(data[i:i+3])


'''
====================================Machine Learning Model=============================================
'''

'''
Training (training up on labeled data)
'''

def machineModelTraining(model):
    file_path = 'Malware dataset\Malware and Benign dataset.csv'

    # this auto detects the encoding type of the file and assigns it to the variable encoding ready to use in the read file argument
    with open(file_path, "rb") as f: 
        result = chardet.detect(f.read())
        encoding = result['encoding']

    df = pd.read_csv(file_path, encoding=encoding)

    # Specify the columns you want to read
    columns_to_read = ['filesize', 'entropy']

    x = df[columns_to_read] #features
    y = df['Label']

    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.3, random_state=42)  

    # fit the model 
    model.fit(x_train, y_train)

    # get a prediction
    y_predlr = model.predict(x_test)

    # Accuracy score using sklearn metrics lib
    print('Accuracy: ' , accuracy_score(y_test, y_predlr))



'''
Execution (looking at new data)
'''

def predictingMalware(model):

    file_path = 'File_DATA.csv'

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



'''
====================================Display Mal File to User (os.remove)===========================================
'''

def getMalwareList():

    mal_list = []

    file_path = 'File_DATA.csv' # come back to switch

    # this auto detects the encoding ype of the file and assigns it to the variable encoding ready to use in the read file argument
    with open(file_path, "rb") as f: 
        result = chardet.detect(f.read())
        encoding = result['encoding']

    df = pd.read_csv(file_path, encoding=encoding)

    predicted_col = df['Predicted Result']
    file_name = df['filename']

    for i in range(len(predicted_col)):
        if predicted_col[i] == 1:
            mal_list.append(file_name[i])

    return mal_list

# displays output to user and asks for an interaction
def userDisplay(mal_list):

    if len(mal_list) == 0:
        print('No malicious files detected')
        end_program = input('Press Enter to end program') 


    print('All detected malicious files')
    
    for item in mal_list:

        print('Would you like to remove: ', item)

        answer = input("Enter Yes or No (Y/N): ")
        answer = answer.upper()

        if answer == 'Y':
            for item in mal_list:
                os.remove(item)
            
            print('All Malicious Files were deleted from your system')
            
        elif answer == 'N':
            print('No Files were not deleted')
        



'''
====================================MAIN=============================================
'''

if __name__ == "__main__":
 
    # folderName = r"C:/Users/Benchmark/Desktop"
    folderName = r"scanMe"
    
    #Scans files within directory
    file_array = scanFiles(folderName)

    print('Scanning complete')

    #Makes csv of all scanned files
    createCSV(file_array)


    print('CSV added to current directory')

    # Instance of model
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    machineModelTraining(model)
    predictingMalware(model)

    # Displays to user a list of all malicious files
    mal_list = getMalwareList()
    userDisplay(mal_list)


    end_program = input('Press Enter to end program') 