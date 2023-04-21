import requests  # pip3 install requests
import hashlib
import sys


def request_api_data(query_char):
    url = f'https://api.pwnedpasswords.com/range/{query_char}'
    response = requests.get(url)
    print(response)
    if response.status_code != 200:
        raise RuntimeError(f'Error fetching: {response.status_code}. Check the api and try again')
    else:
        return response

def get_password_leaks_count(hashes, has_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())  # comprehension
    for h, count in hashes:
        if h == has_to_check:
            return count
    return 0

def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    # send first 5 chars to keep anonymity
    # then, check to see if the full sha1 is returned by the service
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)

def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times. Pilas!')
        else:
            print(f'{password} was NOT found. Melo.')
    return 'done!'

if __name__ == '__main__':
    # since 'argv' values can be accessed somehow, it's recommended to send params in another way, i.e. a text file
    sys.exit(main(sys.argv[1:]))  # sys.exit - to ensure the process is finished and return to the command line

