"""Chromium end-to-end checks against an already-running local workspace.

Run with the webapp-testing with_server.py helper or --url for an owned preview.
"""

import argparse
import ast
import io
import json
from pathlib import Path
import zipfile
from uuid import uuid4

from playwright.sync_api import sync_playwright, expect


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8080")
    parser.add_argument("--screenshots", type=Path, default=Path("artifacts/step7-browser"))
    parser.add_argument("--chromium", default="/opt/google/chrome/chrome" if Path("/opt/google/chrome/chrome").exists() else None)
    args = parser.parse_args()
    args.screenshots.mkdir(parents=True, exist_ok=True)
    errors, checks, job_ids = [], [], []
    run_tag = uuid4().hex[:6]
    def named(title): return f"{title} ({run_tag})"
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, executable_path=args.chromium, args=["--no-sandbox"])
        context = browser.new_context(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce", accept_downloads=True)
        page = context.new_page()
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.goto(args.url)
        page.wait_for_load_state("networkidle")
        page.screenshot(path=str(args.screenshots / "home-desktop.png"), full_page=True)

        def start(title, *, mode="stale_session", lifecycle="sharing_revocation", action="read", target="managed_lab"):
            page.goto(args.url + "/new")
            page.wait_for_load_state("networkidle")
            page.get_by_label("Experiment name").fill(named(title))
            page.get_by_label("Target application").select_option(target)
            if target == "managed_lab":
                page.get_by_label("Lab behavior").select_option(mode)
                page.get_by_label("Permission change").select_option(lifecycle)
                page.get_by_label("Protected action").select_option(action)
            page.get_by_role("button", name="Validate configuration", exact=True).click()
            expect(page.get_by_role("status").filter(has_text="Configuration valid")).to_be_visible()
            page.get_by_role("button", name="Start experiment", exact=True).click()
            page.wait_for_url("**/runs/*")
            identifier = page.url.rsplit("/", 1)[1]
            job_ids.append(identifier)
            return identifier

        stale = start("Stale sharing session · browser check")
        # The worker must continue while the browser leaves the job page.
        page.goto(args.url)
        page.wait_for_load_state("networkidle")
        page.get_by_role("link", name=named("Stale sharing session · browser check"), exact=True).click()
        expect(page.get_by_role("heading", name="Confirmed violation", exact=True)).to_be_visible(timeout=40000)
        expect(page.get_by_role("heading", name="Attempt 1", exact=True)).to_be_visible()
        page.screenshot(path=str(args.screenshots / "confirmed-desktop.png"), full_page=True)
        page.locator("details.event").first.locator("summary").click()
        expect(page.locator("details.event[open]")).to_have_count(1)
        checks.append("browser navigation preserves execution and live confirmation")
        page.get_by_role("link", name="Review evidence", exact=True).click()
        with page.expect_download() as downloaded:
            page.get_by_role("link", name="Download evidence bundle").click()
        destination = args.screenshots / "browser-evidence.zip"
        downloaded.value.save_as(destination)
        with zipfile.ZipFile(destination) as archive:
            ast.parse(archive.read("replay.py").decode())
            manifest = json.loads(archive.read("replay.json"))
            assert manifest["job"]["fixture_mode"] == "stale_session"
            assert any(name.endswith("analysis.json") for name in archive.namelist())
        checks.append("browser evidence download includes replay and oracle observations")

        correct = start("Correct immediate enforcement", mode="immediate")
        expect(page.get_by_role("heading", name="No violation observed", exact=True)).to_be_visible(timeout=20000)
        checks.append("correct lab produces a non-finding through the browser")
        page.get_by_role("button", name="Replay with fresh state").click()
        page.wait_for_url(lambda url: str(url).endswith(correct) is False)
        replay_id = page.url.rsplit("/", 1)[1]
        job_ids.append(replay_id)
        expect(page.get_by_role("heading", name="No violation observed", exact=True)).to_be_visible(timeout=20000)
        checks.append("replay queues a new independently executed job")

        writing = start("Role downgrade · write effect", mode="write_side_effect", lifecycle="role_downgrade", action="write")
        expect(page.get_by_role("heading", name="Confirmed violation", exact=True)).to_be_visible(timeout=40000)
        assert "Protected write" in page.get_by_role("main").inner_text()
        checks.append("browser configuration reaches the protected-write oracle")

        cancelled = start("Cancel a running lab", mode="delayed")
        expect(page.get_by_role("button", name="Cancel experiment", exact=True)).to_be_visible()
        page.get_by_role("button", name="Cancel experiment", exact=True).click()
        expect(page.locator(".badge.cancelled")).to_be_visible(timeout=10000)
        expect(page.get_by_role("heading", name="Confirmed violation", exact=True)).to_have_count(0)
        checks.append("cancellation stops a live job without promoting partial evidence")

        for target in ("pocketbase", "gitea"):
            start(f"Native {target} read", target=target)
            expect(page.get_by_role("heading", name="No violation observed", exact=True)).to_be_visible(timeout=30000)
            checks.append(f"native {target} executes through the browser")

        page.goto(args.url + "/?view=findings")
        page.wait_for_load_state("networkidle")
        expect(page.get_by_role("link", name=named("Stale sharing session · browser check"), exact=True)).to_be_visible()
        expect(page.get_by_role("link", name=named("Correct immediate enforcement"), exact=True)).to_have_count(0)
        checks.append("findings view separates confirmed findings from non-findings")

        page.set_viewport_size({"width": 390, "height": 844})
        page.goto(args.url + "/new")
        page.wait_for_load_state("networkidle")
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
        page.screenshot(path=str(args.screenshots / "new-mobile.png"), full_page=True)
        page.get_by_label("Experiment name").focus()
        assert page.get_by_label("Experiment name").evaluate("e => getComputedStyle(e).outlineStyle !== 'none'")
        page.goto(args.url + "/runs/" + stale)
        page.wait_for_load_state("networkidle")
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
        page.screenshot(path=str(args.screenshots / "confirmed-mobile.png"), full_page=True)
        checks.append("mobile layouts fit 390px and keyboard focus is visible")
        context.close()
        browser.close()
    report = {"checks": checks, "page_errors": errors, "job_ids": job_ids}
    (args.screenshots / "browser-report.json").write_text(json.dumps(report, indent=2)+"\n")
    assert not errors, errors
    print(json.dumps(report, indent=2))


if __name__ == "__main__": main()
