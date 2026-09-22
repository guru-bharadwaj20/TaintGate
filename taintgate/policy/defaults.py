"""Example policy: callers must separately configure allowed tools."""
RECIPIENT_RULES = '''
deny(C) :- untrusted_recipient(C).
deny(C) :- untrusted_control(C).
'''

CONFIDENTIALITY_RULES = '''
deny(C) :- reader_denied(C).
'''

APPROVAL_RULES = '''
ask(C) :- approval_required(C).
'''

def policy_for_tools(tools: list[str] | tuple[str, ...]) -> str:
    import json
    return RECIPIENT_RULES + CONFIDENTIALITY_RULES + APPROVAL_RULES + '\n'.join(
        f'allow(C) :- call(C, {json.dumps(tool)}).' for tool in tools)
