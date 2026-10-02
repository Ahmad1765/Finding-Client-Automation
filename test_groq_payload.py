import urllib.request
import json
import os
import prospector

prompt = "Hello"
payload = json.dumps({
    "model": "llama-3.1-8b-instant",
    "messages": [{"role": "user", "content": prompt}],
    "temperature": 0.7
}).encode('utf-8')

headers = {
    'Content-Type': 'application/json',
    'Authorization': f'Bearer {prospector.GROQ_API_KEY}',
    'User-Agent': 'Mozilla/5.0'
}

req = urllib.request.Request('https://api.groq.com/openai/v1/chat/completions', data=payload, headers=headers)
try:
    with urllib.request.urlopen(req) as response:
        print(response.read().decode())
except urllib.error.HTTPError as e:
    print(f"HTTP Error {e.code}: {e.reason}")
    print(e.read().decode())
except Exception as e:
    print(f"Error: {e}")
