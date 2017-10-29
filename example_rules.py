def get_rules():
    return (
        # Move all mails matching the following rules to folder "Lists"
        ('Lists', (
            # All emails to job mailing list
            ('HEADER', 'List-Id', 'jobs@example.org'),
        )),
        ('Work', (
            ('FROM', 'bob@example.org'),
            ('FROM', 'alice@example.com'),
        )),
    )
