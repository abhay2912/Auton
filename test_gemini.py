import os
import google.generativeai as genai

api_key = os.environ.get("GEMINI_API_KEY")
if not api_key:
    print("GEMINI_API_KEY not set")
    exit(1)

genai.configure(api_key=api_key)

models_to_try = [
    "gemini-1.5-flash",
    "models/gemini-1.5-flash",
    "gemini-1.5-flash-latest",
    "models/gemini-1.5-flash-latest",
    "gemini-1.5-flash-001",
    "models/gemini-1.5-flash-001",
    "gemini-pro",
    "models/gemini-pro"
]

for m_name in models_to_try:
    print(f"Testing {m_name}...")
    try:
        model = genai.GenerativeModel(m_name)
        response = model.generate_content("Hello")
        print(f"SUCCESS with {m_name}: {response.text}")
        break
    except Exception as e:
        print(f"FAILED {m_name}: {e}")
