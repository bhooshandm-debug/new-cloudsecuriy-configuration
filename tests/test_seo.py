def test_robots_txt(client):
    res = client.get("/robots.txt")
    assert res.status_code == 200
    assert res.mimetype == "text/plain"
    content = res.data.decode("utf-8")
    assert "Disallow: /dashboard/" in content
    assert "Disallow: /scans/" in content
    assert "Allow: /login" in content
    assert "Sitemap:" in content


def test_sitemap_xml(client):
    res = client.get("/sitemap.xml")
    assert res.status_code == 200
    assert "xml" in res.mimetype
    content = res.data.decode("utf-8")
    assert "<urlset" in content
    assert "/login" in content
    assert "/register" in content
    assert "/llms.txt" in content


def test_llms_txt(client):
    res = client.get("/llms.txt")
    assert res.status_code == 200
    assert "text/plain" in res.mimetype
    content = res.data.decode("utf-8")
    assert "CloudSec" in content
    assert "Amazon Web Services (AWS)" in content
    assert "Microsoft Azure" in content
    assert "Google Cloud Platform (GCP)" in content


def test_custom_404_page(client):
    res = client.get("/non-existent-security-route-404")
    assert res.status_code == 404
    content = res.data.decode("utf-8")
    assert "Security Resource Not Found" in content
    assert "404" in content
