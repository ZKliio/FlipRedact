import re

text = "The quick brown fox jumps over the lazy dog"
pattern = re.compile(r'quick')

match = pattern.search(text)
if match:
    start, end = match.span()
    print(f"Found 'fox' from position {start} to {end}")
    print(f"Matched text: '{text[start:end]}'")