import urllib.request
import re
import os

fonts_dir = os.path.join(os.getcwd(), "static", "fonts")
os.makedirs(fonts_dir, exist_ok=True)

url = "https://fonts.googleapis.com/css2?family=Instrument+Serif:ital@0;1&family=Inter:wght@400;500;600;700&display=swap"
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

req = urllib.request.Request(url, headers=headers)
try:
    with urllib.request.urlopen(req, timeout=10) as resp:
        css = resp.read().decode('utf-8')
        print("CSS length:", len(css))
        
        # parse font urls
        urls = re.findall(r'url\((https://[^)]+\.woff2)\)', css)
        print("Found woff2 urls:", len(urls))
        for i, u in enumerate(urls):
            filename = f"font_{i}.woff2"
            if "InstrumentSerif" in u or "instrument" in u.lower():
                filename = f"instrument_serif_{i}.woff2"
            elif "inter" in u.lower():
                filename = f"inter_{i}.woff2"
            dest = os.path.join(fonts_dir, filename)
            urllib.request.urlretrieve(u, dest)
            css = css.replace(u, f"/static/fonts/{filename}")
            print(f"Downloaded {filename}")
            
        with open(os.path.join(fonts_dir, "fonts.css"), "w", encoding="utf-8") as f:
            f.write(css)
        print("Saved fonts.css successfully!")
except Exception as e:
    print("Error:", e)
