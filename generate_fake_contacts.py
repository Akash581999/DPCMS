import csv
import random
import time
from faker import Faker  # type: ignore
from datetime import datetime

fake = Faker()

def generate_fake_contacts_csv(filename: str, num_records: int = 1_000_000):
    """
    Generate fake contact data and write to a CSV file,
    while measuring the time taken.
    """
    print(f"📦 Starting generation of {num_records} fake contact records...")

    start_time = time.time()  # ⏱ Start timing

    with open(filename, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow([
            'fullname', 'email', 'mobile_no', 'address',
            'message', 'rating', 'sent_on', 'read_status'
        ])

        for i in range(num_records):
            writer.writerow([
                fake.name(),
                fake.unique.email(),
                fake.phone_number(),
                fake.address().replace("\n", ", "),
                fake.text(max_nb_chars=200),
                random.randint(1, 5),
                datetime.utcnow().isoformat(),
                random.choice(['Unread', 'Read'])
            ])

            # Optional: progress indicator every 100K
            if (i + 1) % 100_000 == 0:
                print(f"✅ {i + 1} records written...")

    end_time = time.time()  # ⏱ End timing

    duration = end_time - start_time
    print(f"\n🎉 Done! CSV written to: {filename}")
    print(f"⏱️ Time taken: {duration:.2f} seconds ({duration / 60:.2f} minutes)")

# Run the generator
generate_fake_contacts_csv("fake_contacts.csv", num_records=1_000_000)