import os
from groq import Groq
from dotenv import load_dotenv

load_dotenv(".env.local")

_client = Groq(api_key=os.environ["GROQ_API_KEY"])

def complete(prompt: str, model: str = "openai/gpt-oss-20b") -> str:
    resp = _client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        temperature=0,          
    )
    return resp.choices[0].message.content
