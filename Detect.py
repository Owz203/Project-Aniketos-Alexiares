import os

def check_signature(file_path):
    try:
        with open(file_path, 'rb') as f:
            signature = f.read(4)
            signature_formatted = signature.hex().upper()
            # print("Signature (Hex):", signature_formatted)
            return signature_formatted
    except FileNotFoundError:
        print(f"file not found: ", file_path)
    except Exception as e:
        print(f"OPeration failed, please tr again.")
        print(f"Error code: ", e)
    


def scanFiles(dir , bad_boy):
    for root,_, files in os.walk(dir):
        for file in files: 
            file_path = os.path.join(root,file)

            file_sig = check_signature(file_path)

            print(file_path)

            if file_sig == bad_boy:
                print("we have a bad boy here")
                # os.remove(file_path) # this deletes the bad boy file
            else:
                print("we good here chief")


if __name__ == '__main__':
    specified_folder = r"IoT app data Master"

    malicious_sig = '504B0304' # this is from a xml file. This is the HEX signature of xml. using this as test plan iss to use api later

    scanFiles(specified_folder,malicious_sig)





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
