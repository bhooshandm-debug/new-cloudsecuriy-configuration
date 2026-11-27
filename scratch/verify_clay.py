import os, sys
sys.path.insert(0, os.getcwd())
from app import create_app

app = create_app()
with app.test_client() as client:
    res = client.get('/static/clay_dashboard.html')
    print("GET /static/clay_dashboard.html ->", res.status_code, len(res.data), "bytes")
    assert res.status_code == 200
    res_css = client.get('/static/css/style.css')
    print("GET /static/css/style.css ->", res_css.status_code, len(res_css.data), "bytes")
    assert res_css.status_code == 200
    res_fonts = client.get('/static/fonts/clay_fonts.css')
    print("GET /static/fonts/clay_fonts.css ->", res_fonts.status_code, len(res_fonts.data), "bytes")
    assert res_fonts.status_code == 200
print("Verification successful!")
