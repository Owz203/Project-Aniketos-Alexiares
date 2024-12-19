import requests


api_key = 'df0a7189edcaae2f0222ed508124fcf0f352d52d299fa5ffdde3fcb58d2a83c5'
hash_file = 'f41dae8000c147cd6719337a9f2d107e1dd0f9704ae8c59b1abcbc7d5b6f2b42'
url = "https://www.virustotal.com/api/v3/files/" + hash_file


headers = {
    "accept": "application/json",
    "x-apikey": api_key
}

response = requests.get(url, headers=headers)

print(response.text)