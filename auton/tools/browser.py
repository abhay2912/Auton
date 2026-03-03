"""
Browser tools for Auton v2.

Optimized for pentest efficiency:
- SessionPool replaces single global _driver
- visit_page returns title + URL + DOM summary (forms, links, inputs)
- click_element returns new URL + page state
- fill_form_input returns confirmation with value echoed
- All operations scoped to a named session for clean parallelism
"""

import time
from typing import Optional, Dict, List
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from auton.tools.registry import registry


# ─── Session Pool ────────────────────────────────────────────

class BrowserSession:
    """An isolated browser context with its own driver, cookies, and auth role."""
    
    def __init__(self, name: str, auth_role: str = "anonymous", 
                 headless: bool = False, proxy: Optional[str] = None):
        self.name = name
        self.auth_role = auth_role
        self.cookies: Dict[str, str] = {}
        
        options = Options()
        options.add_argument("--ignore-certificate-errors")
        options.add_argument("--disable-quic")
        options.add_argument("--disable-webrtc")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        
        if headless:
            options.add_argument("--headless=new")
        if proxy:
            options.add_argument(f"--proxy-server={proxy}")
        
        print(f"[Browser] Creating session '{name}' (role={auth_role})")
        self.driver = webdriver.Chrome(
            service=ChromeService(ChromeDriverManager().install()), 
            options=options
        )
        self.driver.set_page_load_timeout(30)
    
    def close(self):
        if self.driver:
            self.driver.quit()
            self.driver = None
            print(f"[Browser] Session '{self.name}' closed")


class SessionPool:
    """
    Pool of isolated browser sessions, one per auth role.
    
    Usage:
        pool.create("anonymous")
        pool.create("userA", cookies={"session": "abc"})
        driver = pool.get("anonymous").driver
        pool.destroy("userA")
    """
    
    def __init__(self):
        self.sessions: Dict[str, BrowserSession] = {}
        self._default_session: Optional[str] = None
    
    def create(self, name: str, auth_role: str = "anonymous",
               headless: bool = False, proxy: Optional[str] = None,
               cookies: Optional[Dict[str, str]] = None) -> BrowserSession:
        """Create a new isolated browser session."""
        if name in self.sessions:
            print(f"[SessionPool] Session '{name}' already exists, reusing")
            return self.sessions[name]
        
        session = BrowserSession(name, auth_role, headless, proxy)
        
        if cookies:
            session.cookies = cookies
        
        self.sessions[name] = session
        
        if self._default_session is None:
            self._default_session = name
        
        return session
    
    def get(self, name: Optional[str] = None) -> BrowserSession:
        """Get a session by name, or the default session."""
        target = name or self._default_session
        
        if target is None or target not in self.sessions:
            # Auto-create a default session
            return self.create("default")
        
        return self.sessions[target]
    
    def destroy(self, name: str) -> None:
        """Close and remove a session."""
        if name in self.sessions:
            self.sessions[name].close()
            del self.sessions[name]
            if self._default_session == name:
                self._default_session = next(iter(self.sessions), None)
    
    def destroy_all(self) -> None:
        """Close all sessions."""
        for session in list(self.sessions.values()):
            session.close()
        self.sessions.clear()
        self._default_session = None
    
    def list_sessions(self) -> List[Dict]:
        """List all active sessions."""
        return [
            {"name": s.name, "role": s.auth_role, "url": s.driver.current_url if s.driver else "closed"}
            for s in self.sessions.values()
        ]


# Global session pool
session_pool = SessionPool()


def _get_driver(session: Optional[str] = None):
    """Get the WebDriver for a named session (backward compatible)."""
    return session_pool.get(session).driver


# ─── DOM Analysis Helpers ────────────────────────────────────

def _extract_page_summary(driver) -> str:
    """Extract a compact, pentest-relevant summary of the current page."""
    parts = []
    parts.append(f"URL: {driver.current_url}")
    parts.append(f"Title: {driver.title}")
    
    try:
        # Forms
        forms = driver.find_elements(By.TAG_NAME, "form")
        if forms:
            parts.append(f"\nForms ({len(forms)}):")
            for i, form in enumerate(forms[:5]):
                action = form.get_attribute("action") or "(self)"
                method = form.get_attribute("method") or "GET"
                inputs = form.find_elements(By.TAG_NAME, "input")
                textareas = form.find_elements(By.TAG_NAME, "textarea")
                selects = form.find_elements(By.TAG_NAME, "select")
                
                input_details = []
                for inp in inputs:
                    itype = inp.get_attribute("type") or "text"
                    iname = inp.get_attribute("name") or inp.get_attribute("id") or "unnamed"
                    input_details.append(f"{iname}({itype})")
                for ta in textareas:
                    tname = ta.get_attribute("name") or ta.get_attribute("id") or "unnamed"
                    input_details.append(f"{tname}(textarea)")
                for sel in selects:
                    sname = sel.get_attribute("name") or sel.get_attribute("id") or "unnamed"
                    input_details.append(f"{sname}(select)")
                
                parts.append(f"  [{i}] {method.upper()} {action} → {', '.join(input_details)}")
        
        # Links (unique, capped)
        links = driver.find_elements(By.TAG_NAME, "a")
        unique_hrefs = set()
        for link in links:
            href = link.get_attribute("href")
            if href and href.startswith("http"):
                unique_hrefs.add(href)
        
        if unique_hrefs:
            parts.append(f"\nLinks ({len(unique_hrefs)} unique):")
            for href in list(unique_hrefs)[:10]:
                parts.append(f"  {href}")
            if len(unique_hrefs) > 10:
                parts.append(f"  ... and {len(unique_hrefs) - 10} more")
        
        # Input fields outside forms
        standalone_inputs = driver.find_elements(By.CSS_SELECTOR, "input:not(form input)")
        if standalone_inputs:
            parts.append(f"\nStandalone inputs ({len(standalone_inputs)}):")
            for inp in standalone_inputs[:5]:
                itype = inp.get_attribute("type") or "text"
                iname = inp.get_attribute("name") or inp.get_attribute("id") or "unnamed"
                parts.append(f"  {iname} ({itype})")
        
    except Exception as e:
        parts.append(f"\n[DOM analysis error: {e}]")
    
    return "\n".join(parts)


# ─── Registered Tools ───────────────────────────────────────

@registry.register
def visit_page(url: str, session: str = "default") -> str:
    """
    Navigates the browser to the specified URL.
    Returns page title, URL, forms, links, and input fields.
    
    Args:
        url: The URL to visit (must start with http/https).
        session: Browser session name (default: 'default').
    """
    try:
        driver = _get_driver(session)
        print(f"[Browser] Navigating to {url} (session: {session})")
        driver.get(url)
        time.sleep(2)  # Wait for JS
        return _extract_page_summary(driver)
    except Exception as e:
        return f"Error visiting page: {e}"


@registry.register
def get_computed_dom(session: str = "default") -> str:
    """
    Returns the current full HTML source of the page.
    Use this to inspect the page state after actions.
    
    Args:
        session: Browser session name (default: 'default').
    """
    try:
        driver = _get_driver(session)
        return driver.page_source
    except Exception as e:
        return f"Error getting DOM: {e}"


@registry.register
def execute_js(script: str, session: str = "default") -> str:
    """
    Executes a JavaScript snippet in the browser.
    
    Args:
        script: The JS code to run.
        session: Browser session name (default: 'default').
    """
    try:
        driver = _get_driver(session)
        result = driver.execute_script(script)
        return str(result)
    except Exception as e:
        return f"Error executing JS: {e}"


@registry.register
def click_element(selector: str, session: str = "default") -> str:
    """
    Clicks an element on the current page.
    Returns new URL, page title, and key DOM changes after click.
    
    Args:
        selector: CSS selector for the element (e.g., '#submit-btn', '.nav-link').
        session: Browser session name (default: 'default').
    """
    try:
        driver = _get_driver(session)
        old_url = driver.current_url
        
        element = driver.find_element(By.CSS_SELECTOR, selector)
        element_text = element.text[:50] if element.text else "(no text)"
        element.click()
        time.sleep(1)  # Wait for reaction
        
        new_url = driver.current_url
        navigated = f"\nNavigation: {old_url} → {new_url}" if new_url != old_url else ""
        
        result = f"Clicked: {selector} (text: '{element_text}')"
        result += navigated
        result += f"\nCurrent page: {driver.title}"
        result += f"\nURL: {new_url}"
        
        # Check for alerts
        try:
            alert = driver.switch_to.alert
            alert_text = alert.text
            result += f"\n⚠ ALERT DIALOG: '{alert_text}'"
            alert.accept()
        except Exception:
            pass
        
        return result
    except Exception as e:
        return f"Error clicking element: {e}"


@registry.register
def fill_form_input(selector: str, value: str, session: str = "default") -> str:
    """
    Types text into an input field or textarea.
    Returns confirmation with the value echoed.
    
    Args:
        selector: CSS selector for the input element.
        value: The text to type.
        session: Browser session name (default: 'default').
    """
    try:
        driver = _get_driver(session)
        element = driver.find_element(By.CSS_SELECTOR, selector)
        
        field_name = (element.get_attribute("name") or 
                     element.get_attribute("id") or selector)
        field_type = element.get_attribute("type") or "text"
        
        element.clear()
        element.send_keys(value)
        
        # Read back the actual value
        actual = element.get_attribute("value")
        
        return f"Filled '{field_name}' ({field_type}) with: '{value}' → confirmed value: '{actual}'"
    except Exception as e:
        return f"Error filling input: {e}"


@registry.register
def manage_session(action: str, name: str = "default", 
                   auth_role: str = "anonymous") -> str:
    """
    Manage browser sessions for multi-role testing.
    
    Args:
        action: 'create', 'list', 'destroy', or 'destroy_all'.
        name: Session name (for create/destroy).
        auth_role: Auth role label (for create).
    """
    try:
        if action == "create":
            session_pool.create(name, auth_role=auth_role)
            return f"Session '{name}' created (role: {auth_role})"
        elif action == "list":
            sessions = session_pool.list_sessions()
            if not sessions:
                return "No active sessions"
            lines = [f"  {s['name']}: role={s['role']}, url={s['url']}" for s in sessions]
            return "Active sessions:\n" + "\n".join(lines)
        elif action == "destroy":
            session_pool.destroy(name)
            return f"Session '{name}' destroyed"
        elif action == "destroy_all":
            session_pool.destroy_all()
            return "All sessions destroyed"
        else:
            return f"Unknown action: {action}. Use create/list/destroy/destroy_all."
    except Exception as e:
        return f"Error managing session: {e}"


@registry.register
def close_browser() -> str:
    """
    Closes all browser sessions and ends all browser activity.
    """
    session_pool.destroy_all()
    return "All browser sessions closed."
