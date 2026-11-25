# CareShield — CS-3002 Assignment 4

## Run locally
1. Install Python 3.10+.
2. Open a terminal in this folder.
3. Run `python -m venv .venv` and activate it.
4. Run `pip install -r requirements.txt`.
5. Run `streamlit run app.py`.
6. Open the local URL printed by Streamlit.

## Demo accounts
| Role | Username | Password |
|---|---|---|
| Admin | admin | admin123 |
| Doctor | doctor | doc123 |
| Receptionist | receptionist | rec123 |

The SQLite database (`hospital.db`) and Fernet key (`fernet.key`) are created automatically.
Keep `fernet.key` private and back it up securely; without it encrypted values cannot be
recovered. The dashboard intentionally keeps doctor access to anonymized records and
does not expose raw data to receptionists.

## Screenshots for submission
Run the app and capture genuine screenshots of:
1. Login page.
2. Admin dashboard after clicking **Anonymize all records**.
3. Admin **Integrity Audit Log** tab.
Replace the illustrative preview images in the report with your own screenshots.

## Important limitations
This is an educational prototype, not a certified hospital system or legal GDPR compliance
solution. Demo credentials must be changed. Production use requires HTTPS, secret management,
stronger account lifecycle controls, encrypted backups, access reviews, retention/deletion
workflows, consent records with purpose and withdrawal, and professional security/legal review.
