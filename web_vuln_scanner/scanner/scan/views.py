from django.shortcuts import render
from django.http import HttpResponse
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import requests

SQLI_PAYLOADS = ["'", '"', " OR 1=1 --", "' OR '1'='1"]
SCAN_RESULT = {}

def scan_url(request):
    result = None
    s = False
    x = False
    security_headers = {}

    if request.method == "POST":
        url = request.POST.get("url")
        try:
            response = requests.get(url)
            page_content = response.text[:1000] 
            security_headers = response.headers  

            for payload in SQLI_PAYLOADS:
                test_url = url + payload
                test_response = requests.get(test_url)
                if "sql" in test_response.text.lower() or "database" in test_response.text.lower():
                    s = True
                    break  
        
            xss_payload = "<script>alert('XSS')</script>"
            xss_test_url = f"{url}/?q={xss_payload}"
            xss_response = requests.get(xss_test_url)
            if xss_payload in xss_response.text:
                x = True

            result = {
                "content": page_content,
                "sqli_vulnerable": s,
                "xss_vulnerable": x,
                "security_headers": dict(security_headers),
            }
            SCAN_RESULT = result
        except requests.exceptions.RequestException as e:
            result = {"error": str(e)}

    return render(request, "index.html", {"result": result})


def download_report(request):
    global SCAN_RESULT
    response = HttpResponse(content_type="application/pdf")
    response["Content-Disposition"] = 'attachment; filename="scan_report.pdf"'

    p = canvas.Canvas(response, pagesize=letter)
    p.setFont("Helvetica", 12)

    p.drawString(100, 750, "Web Application Vulnerability Scan Report")
    p.line(100, 745, 500, 745)

    if SCAN_RESULT:
        p.drawString(100, 720, f"URL Scanned: {SCAN_RESULT.get('url', 'N/A')}")

        p.drawString(100, 700, "SQL Injection:")
        if SCAN_RESULT.get("sqli_vulnerable"):
            p.setFillColorRGB(1, 0, 0)
            p.drawString(200, 700, "⚠️ Vulnerable")
        else:
            p.setFillColorRGB(0, 1, 0)
            p.drawString(200, 700, "✅ No vulnerability detected")

        p.setFillColorRGB(0, 0, 0)
        p.drawString(100, 680, "Cross-Site Scripting (XSS):")
        if SCAN_RESULT.get("xss_vulnerable"):
            p.setFillColorRGB(1, 0, 0)
            p.drawString(200, 680, "⚠️ Vulnerable")
        else:
            p.setFillColorRGB(0, 1, 0)
            p.drawString(200, 680, "✅ No vulnerability detected")

        p.setFillColorRGB(0, 0, 0)
        p.drawString(100, 660, "Security Headers:")
        y = 640
        for key, value in SCAN_RESULT.get("security_headers", {}).items():
            p.drawString(120, y, f"{key}: {value}")
            y -= 20

    p.showPage()
    p.save()

    return response
