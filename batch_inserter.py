import threading
import time
from import_csv_to_db import insert_fake_contacts

batch_inserting = False
batch_thread = None
stop_event = threading.Event()  # ✅ This lets us interrupt sleep

def batch_insert_loop(app, interval=300):
    global batch_inserting
    with app.app_context():
        while not stop_event.is_set():  # ✅ Keep running unless stop is signaled
            print("📥 Inserting 10 records...")
            insert_fake_contacts()
            # Wait for the interval, but interruptible
            if stop_event.wait(interval):  # Returns True if stop_event was set during wait
                break
        print("🛑 Batch insert loop stopped.")
        batch_inserting = False  # Reset state when thread ends

def start_batch_insert(app, interval=300):
    global batch_inserting, batch_thread, stop_event
    if not batch_inserting:
        stop_event.clear()  # ✅ Clear stop signal
        batch_inserting = True
        batch_thread = threading.Thread(target=batch_insert_loop, args=(app, interval), daemon=True)
        batch_thread.start()
        return True
    return False

def stop_batch_insert():
    global batch_inserting, stop_event
    if batch_inserting:
        stop_event.set()  # ✅ Trigger to stop the thread
        return True
    return False

def is_batch_inserting():
    global batch_inserting
    return batch_inserting