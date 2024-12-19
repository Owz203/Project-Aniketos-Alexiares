import os
import requests
import hashlib
import json

def getFileHash(file_name):
    algorithm='sha256'
    hash_func = hashlib.new(algorithm) # Compute the hash of a file using the specified algorithm.
    
    try:
        with open(file_name, 'rb') as file:
            while chunk := file.read(8192):  # Read the file in chunks of 8192 bytes
                hash_func.update(chunk)
    except FileNotFoundError:
        print(f"file not found: ", file_name)
    except Exception as e:
        print(f"Operation failed, please tr again.")
        print(f"Error code: ", e)
    
    # print(hash_func.hexdigest())
    return hash_func.hexdigest()


def scanFiles(dir , api_key):
    for root,_, files in os.walk(dir):
        for file in files: 
            file_path = os.path.join(root,file)

            print('Scanning file: ', file_path) # displays file in question
            # file_sig = check_signature(file_path) # checks integrity 

            file_hash = getFileHash(file_path)

            if not file_hash:
                print('Could not hash file. Skipping file')
                continue

            url = "https://www.virustotal.com/api/v3/files/" + file_hash

            headers = {
                "accept": "application/json",
                "x-apikey": api_key
            }

            response = requests.get(url, headers=headers)

            if response.status_code !=200:
                print('Error: failed to get response')
                continue

            data = response.text
            parsed_data = json.loads(data) # Parse the JSON string

            if "error" in parsed_data:
                error_messsage = parsed_data["error"].get("message",  "Unknown error")
                print("Error: ", error_messsage)
                continue


            stats = parsed_data["data"].get("attributes").get("sigma_analysis_stats")

            crit_val = stats.get('critical')
            high_val = stats.get('high')
            med_val = stats.get('medium')
            low_val = stats.get('low')

            if crit_val > 0:
                print('Potential Malware. Critical score: ', crit_val)
                print('Would you like to remove file: ', file_path)
                answer = input("Enter Yes or No (Y/N): ")            
            elif high_val > 0: 
                print('Potential Malware. Critical score: ', high_val)
                print('Would you like to remove file: ', file_path)
                answer = input("Enter Yes or No (Y/N): ")
            elif med_val > 0: 
                print('Potential Malware. Critical score: ', med_val)
                print('Would you like to remove file: ', file_path)
                answer = input("Enter Yes or No (Y/N): ")
            elif low_val > 0: 
                print('Potential Malware. Critical score: ', low_val)
                print('Would you like to remove file: ', file_path)
                answer = input("Enter Yes or No (Y/N): ")
            
            answer = answer.upper()

            if answer == 'Y':
                os.remove(file_path)
                print('File was deleted from your system')

            elif answer == 'N':
                print('File was not deleted')




if __name__ == '__main__':
    specified_folder = r"C:\Users\Benchmark\Desktop\ScanMe"
    # specified_folder = r"scanME"


    malicious_sig = '504B0304' # this is from a xml file. This is the HEX signature of xml. using this as test plan iss to use api later

    api_key = 'df0a7189edcaae2f0222ed508124fcf0f352d52d299fa5ffdde3fcb58d2a83c5'
    hash_file = 'f41dae8000c147cd6719337a9f2d107e1dd0f9704ae8c59b1abcbc7d5b6f2b42'

    scanFiles(specified_folder, api_key)





# def isFileCorrupted(file_path, expected_sig):
#     try:
#         with open(file_path,"rb") as file:
#             actual_sig =file.read(len(expected_sig))
#             print(actual_sig)
#             return actual_sig == expected_sig
#     except FileNotFoundError:
#         print(f"file not found: ", file_path)
#     except Exception as e:
#         print(f"OPeration failed, please tr again.")
#         print(f"Error code: ", e)


# def check_signature(file_path):
#     try:
#         with open(file_path, 'rb') as f:
#             signature = f.read(4)
#             signature_formatted = signature.hex().upper()
#             # print("Signature (Hex):", signature_formatted)
#             return signature_formatted
#     except FileNotFoundError:
#         print(f"file not found: ", file_path)
#     except Exception as e:
#         print(f"Operation failed, please tr again.")
#         print(f"Error code: ", e)



# for stat , score in stats.items():
#     print(stat , score)












