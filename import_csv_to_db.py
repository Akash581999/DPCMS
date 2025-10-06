import csv
from datetime import datetime
import os
from models import db, Users

def import_csv_to_db(csv_file="users.csv"):
    from app import app  # Avoid circular imports

    with app.app_context():
        with open(csv_file, newline='', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            imported_count = 0

            for row in reader:
                if Users.query.filter_by(email=row['email']).first():
                    continue  # Skip existing users by email

                try:
                    user = Users(
                        full_name=row['full_name'],
                        email=row['email'],
                        mobile_no=row['mobile_no'],
                        address=row['address'],
                        password_hash=row['password_hash'],
                        is_active=True,
                        created_at=datetime.utcnow(),
                        updated_at=datetime.utcnow(),
                        role_id=int(row['role_id']),
                        department_id=int(row['department_id']),
                        company_id=int(row['company_id']),
                    )
                    db.session.add(user)
                    imported_count += 1
                except Exception as e:
                    print(f"❌ Error importing user {row['email']}: {e}")
                    continue

            db.session.commit()
            print(f"✅ Imported {imported_count} users from {csv_file}")

import time
from models import Contacts, ReadStatusEnum  # adjust as per your project

def import_contacts_from_csv(filename: str, batch_size: int = 5000):
    """
    Import contacts from a CSV file into the database.
    Displays time taken and uses batch commits for performance.
    """
    print(f"📥 Starting import from: {filename}")
    start_time = time.time()  # ⏱ Start timing

    with open(filename, mode='r', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        batch = []

        for i, row in enumerate(reader, start=1):
            contact = Contacts(
                fullname=row['fullname'],
                email=row['email'],
                mobile_no=row['mobile_no'],
                address=row.get('address'),
                message=row['message'],
                rating=int(row['rating']) if row['rating'] else None,
                sent_on=datetime.fromisoformat(row['sent_on']),
                read_status=ReadStatusEnum[row['read_status']]  # Enum lookup
            )
            batch.append(contact)

            if len(batch) >= batch_size:
                db.session.bulk_save_objects(batch)
                db.session.commit()
                print(f"✅ Imported {i} records so far...")
                batch = []

        # Commit any remaining records
        if batch:
            db.session.bulk_save_objects(batch)
            db.session.commit()
            print(f"✅ Imported {i} records total.")

    end_time = time.time()  # ⏱ End timing
    duration = end_time - start_time

    print(f"\n🎉 Import complete for file: {filename}")
    print(f"⏱️ Time taken: {duration:.2f} seconds ({duration / 60:.2f} minutes)")

from models import Contacts, ReadStatusEnum, db
import csv, os
from datetime import datetime

record_pointer = {'index': 0}
CSV_FILE = os.path.join(os.getcwd(), 'fake_contacts.csv')

def insert_fake_contacts(batch_size=10):
    print("⏳ Inserting 10 fake records...")

    if not os.path.exists(CSV_FILE):
        print(f"❌ CSV file not found: {CSV_FILE}")
        return

    with open(CSV_FILE, mode='r', encoding='utf-8') as file:
        reader = list(csv.DictReader(file))
        start = record_pointer['index']
        end = start + batch_size
        batch = reader[start:end]

        if not batch:
            print("✅ No more records left to insert.")
            return

        for row in batch:
            contact = Contacts(
                fullname=row['fullname'],
                email=row['email'],
                mobile_no=row['mobile_no'],
                address=row.get('address'),
                message=row['message'],
                rating=int(row['rating']) if row['rating'] else None,
                sent_on=datetime.fromisoformat(row['sent_on']),
                read_status=ReadStatusEnum[row['read_status']]
            )
            db.session.add(contact)

        db.session.commit()
        record_pointer['index'] = end
        print(f"✅ Inserted records {start + 1} to {end}")
