# Scholarship Radar – My Funding Plan 2027

A static lookup page where each Scholarship Radar applicant opens their own funding plan
(fully funded Master's/PhD options in South Korea, Malaysia and Thailand, plus suggested supervisors)
by entering the phone number they gave on the form and one of their names.

**Privacy:** every plan is encrypted (AES-GCM, key from PBKDF2-SHA256 of phone/email + name).
This repository holds only ciphertext and public scholarship/supervisor information. No names,
phone numbers or emails of applicants are stored in readable form, and the lookup runs entirely
in the visitor's browser.
