from http import client
from time import sleep
import web3
import requests
import api_client

# Local
node = {
    "rpc": "http://localhost:7070",
    "api_private_key" : "0xd0fe2cd59aafc8e628be2ea98e1c69b454e33d1b067944641585921a3109498f",
}

api = api_client.API(node)

password = "123456222"
new_pass = "123456111"
sec = 1

if __name__ == "__main__":
    assert(api.is_locked())
    print("Locked. Unlocking....")

    assert(api.unlock("abcdef", sec) == "incorrect_password")
    
    result = api.unlock(password, sec)
    assert(result == "unlocked")
    assert(not api.is_locked())
    print("Unlocked!!!")
    
    sleep(sec+1)
    assert(api.is_locked())
    print("Locked again")

    assert(api.changePassword("abcde", new_pass) == "incorrect_current_password");
    assert(api.changePassword(password, new_pass) == "password_changed");
    print("Pasword changed to " + new_pass)

    result = api.unlock(password, sec)
    assert(result == "incorrect_password")
    assert(api.is_locked())
    print("Cannot unlock With New Password!!!")

    result = api.unlock(new_pass, sec)
    assert(result == "unlocked")
    assert(not api.is_locked())
    print("Unlocked With New Password!!!")
    


