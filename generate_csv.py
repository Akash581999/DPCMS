import csv
import time
from faker import Faker  # type: ignore
import random
import string

fake = Faker()

def generate_random_password(length=10):
    characters = string.ascii_letters + string.digits + "!@#$%^&*()"
    return ''.join(random.choice(characters) for _ in range(length))

def generate_csv(filename="users.csv", count=100000):
    start_time = time.time()  # ⏱️ Start timing

    with open(filename, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow([
            'full_name',
            'email',
            'mobile_no',
            'address',
            'password_hash',
            'role_id',
            'department_id',
            'company_id'
        ])

        for i in range(1, count + 1):
            writer.writerow([
                fake.name(),
                fake.email(),
                fake.phone_number(),
                fake.address().replace('\n', ', '),
                generate_random_password(10),
                2,  # role_id
                1,  # department_id
                1   # company_id
            ])

    end_time = time.time()  # ⏱️ End timing
    elapsed_time = end_time - start_time

    print(f"{count} users written to {filename}")
    print(f"Time taken: {elapsed_time:.2f} seconds")  # ⏱️ Print elapsed time

generate_csv()