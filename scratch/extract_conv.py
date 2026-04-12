import json

with open("../Checkpoints/conversation-69d8dec9e062e60510c74bb2.json", "r") as f:
    data = json.load(f)

# The structure depends on the export format. Let's try dumping human messages or the last few messages.
try:
    if isinstance(data, list): # maybe ChatGPT export
        for msg in data:
            if "message" in msg and msg["message"] and msg["message"].get("author", {}).get("role") == "user":
                parts = msg["message"].get("content", {}).get("parts", [])
                text = "".join(str(p) for p in parts)
                if "missing" in text.lower() or "tool" in text.lower() or "ai" in text.lower() or "checkpoint" in text.lower():
                    print("User message snippet:", text[:300].replace('\n', ' '))
    elif isinstance(data, dict):
        mapping = data.get("mapping", {})
        for k, v in mapping.items():
            msg = v.get("message")
            if msg and msg.get("author", {}).get("role") == "user":
                parts = msg.get("content", {}).get("parts", [])
                text = "".join(str(p) for p in parts)
                if "missing" in text.lower() or "tool" in text.lower() or "ai" in text.lower() or "checkpoint" in text.lower():
                    print("User message snippet:", text[:300].replace('\n', ' '))
except Exception as e:
    print(e)
