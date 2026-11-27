import os
import sys
sys.path.insert(0, os.getcwd())

from app import create_app
from models.user import User

app = create_app()

with app.test_client() as client:
    # 1. Unauthenticated routes
    for path in ["/login", "/register", "/forgot-password"]:
        res = client.get(path)
        print(f"GET {path} -> {res.status_code}")
        assert res.status_code == 200, f"Failed on {path}"
        
    # 2. Login as existing user
    with app.app_context():
        user = User.query.first()
        username = user.username if user else "testadmin"
        print(f"Testing with user: {username} (admin: {user.is_admin if user else False})")
        user_id = str(user.id) if user else "1"
        is_admin = user.is_admin if user else True
        
    # Login via session
    with client.session_transaction() as sess:
        sess["_user_id"] = user_id
        sess["_fresh"] = True
        
    # 3. Authenticated routes
    auth_paths = [
        "/",
        "/accounts/",
        "/scans/",
        "/findings/",
        "/scans/compare",
        "/assistant/",
        "/reports/",
    ]
    if is_admin:
        auth_paths.append("/admin/")
        
    for path in auth_paths:
        res = client.get(path)
        print(f"GET {path} -> {res.status_code} ({len(res.data)} bytes)")
        assert res.status_code == 200, f"Failed on {path} with status {res.status_code}"
        
    # 4. Check CSS & Font assets
    css_res = client.get("/static/css/style.css")
    print(f"GET /static/css/style.css -> {css_res.status_code} ({len(css_res.data)} bytes)")
    assert css_res.status_code == 200
    
    font_res = client.get("/static/fonts/fonts.css")
    print(f"GET /static/fonts/fonts.css -> {font_res.status_code} ({len(font_res.data)} bytes)")
    assert font_res.status_code == 200

print("\nALL ROUTES AND ASSETS VERIFIED SUCCESSFULLY!")
