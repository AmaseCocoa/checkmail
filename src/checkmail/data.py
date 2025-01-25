import regex

REGEX_DOMAIN = r'[\w-]+([-\.]{1}[\w-]+)*\.\w{2,63}'
REGEX_EMAIL_PATTERN = r'^[\w\-\.]{1,255}@(' + REGEX_DOMAIN + r')$'
REGEX_DOMAIN_PATTERN = r'^[\w-]+([-\.]{1}[\w-]+)*\.\w{2,63}$'
REGEX_DOMAIN_FROM_EMAIL = r'^[^@]+@(.+)$'
REGEX_SMTP_ERROR_BODY_PATTERN = r'(?=.*550)(?=.*(user|account|customer|mailbox)).*'
WHITELISTED_EMAILS = "".split(",")

compiled_regex_domain = regex.compile(REGEX_DOMAIN, regex.IGNORECASE)
compiled_regex_email_pattern = regex.compile(REGEX_EMAIL_PATTERN, regex.IGNORECASE)
compiled_regex_domain_pattern = regex.compile(REGEX_DOMAIN_PATTERN, regex.IGNORECASE)
compiled_regex_domain_from_email = regex.compile(REGEX_DOMAIN_FROM_EMAIL)
compiled_regex_smtp_error_body_pattern = regex.compile(REGEX_SMTP_ERROR_BODY_PATTERN, regex.IGNORECASE)