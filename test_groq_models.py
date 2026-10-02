import urllib.request
import prospector

headers = {
    'Authorization': f'Bearer {prospector.GROQ_API_KEY}',
    'User-Agent': 'Mozilla/5.0'
}

req = urllib.request.Request('https://api.groq.com/openai/v1/models', headers=headers)
try:
    with urllib.request.urlopen(req) as response:
        print(response.read().decode())
except Exception as e:
    print(f"Error: {e}")
