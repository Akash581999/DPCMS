import csv
from models import Users

def export_db_to_csv(output_file="exported_users.csv"):
    # Import app only when needed to avoid circular import
    from app import app  

    with app.app_context():
        users = Users.query.all()

        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)

            # ✅ Full header matching the import format
            writer.writerow([
                'user_id',
                'full_name',
                'email',
                'mobile_no',
                'address',
                'password_hash',
                'role_id',
                'department_id',
                'company_id'
            ])

            for user in users:
                writer.writerow([
                    user.user_id,
                    user.full_name,
                    user.email,
                    user.mobile_no,
                    user.address,
                    user.password_hash,
                    user.role_id,
                    user.department_id,
                    user.company_id
                ])

    print(f"✅ Exported {len(users)} users to {output_file}")

if __name__ == "__main__":
    export_db_to_csv()


import csv
import time
from models import Contacts

def export_contacts_to_csv(filepath: str):
    """
    Export all contacts from the database to a CSV file and print time taken.
    """
    print(f"📤 Starting export to: {filepath}")
    start_time = time.time()  # ⏱ Start timing

    # Fetch records (include this in timing)
    contacts = Contacts.query.all()

    with open(filepath, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow([
            'id', 'fullname', 'email', 'mobile_no', 'address',
            'message', 'rating', 'sent_on', 'read_status'
        ])
        for c in contacts:
            writer.writerow([
                c.id,
                c.fullname,
                c.email,
                c.mobile_no,
                c.address,
                c.message,
                c.rating,
                c.sent_on.isoformat() if c.sent_on else '',
                c.read_status.name if c.read_status else ''
            ])

    end_time = time.time()  # ⏱ End timing
    duration = end_time - start_time

    print(f"\n✅ Export complete: {filepath}")
    print(f"⏱️ Time taken: {duration:.2f} seconds ({duration / 60:.2f} minutes)")