"""Example policy: callers must separately configure allowed tools."""
RECIPIENT_RULES = '''
deny(C) :- untrusted_recipient(C).
deny(C) :- untrusted_control(C).
'''

CONFIDENTIALITY_RULES = '''
deny(C) :- reader_denied(C).
'''
