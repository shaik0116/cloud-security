import asyncio
import glob
import os
from playwright.async_api import async_playwright

async def take_screenshot():
    # Find the most recent report file
    reports = glob.glob('security_report_*.html')
    if not reports:
        print("No report found. Run day1_iam_audit.py first.")
        return
    
    latest_report = max(reports)
    print(f"Taking screenshot of: {latest_report}")
    
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page    = await browser.new_page(viewport={'width': 1200, 'height': 800})
        
        # Open the HTML file
        abs_path = os.path.abspath(latest_report)
        await page.goto(f'file:///{abs_path}')
        
        # Take full page screenshot
        await page.screenshot(
            path='security_report.png',
            full_page=True
        )
        
        await browser.close()
        print("✅ Screenshot saved as security_report.png")
        print("   Find it in your devsecops folder")

asyncio.run(take_screenshot())