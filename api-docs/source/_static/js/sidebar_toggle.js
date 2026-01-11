(() => {
  const STORAGE_KEY = "bn_api_sidebar";
  const CLASS_NAME = "bn-sidebar-collapsed";
  const BUTTON_ID = "bn-sidebar-toggle";

  function isCollapsed() {
    return document.documentElement.classList.contains(CLASS_NAME);
  }

  function setCollapsed(collapsed) {
    document.documentElement.classList.toggle(CLASS_NAME, collapsed);
    try {
      localStorage.setItem(STORAGE_KEY, collapsed ? "collapsed" : "expanded");
    } catch (_) {
      // ignore storage failures (private mode, policy, etc.)
    }
    const btn = document.getElementById(BUTTON_ID);
    if (btn) {
      btn.setAttribute("aria-pressed", collapsed ? "true" : "false");
      btn.title = collapsed ? "Show navigation" : "Hide navigation";
    }
  }

  function initialCollapsed() {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved === "collapsed") return true;
      if (saved === "expanded") return false;
    } catch (_) {
      // ignore
    }

    // Default: collapse in narrower / split-screen-ish layouts.
    return window.matchMedia("(max-width: 1400px)").matches;
  }

  function ensureButton() {
    if (document.getElementById(BUTTON_ID)) return;

    const btn = document.createElement("button");
    btn.id = BUTTON_ID;
    btn.type = "button";
    btn.setAttribute("aria-label", "Toggle navigation");
    btn.setAttribute("aria-pressed", "false");
    btn.textContent = "☰";

    btn.addEventListener("click", () => setCollapsed(!isCollapsed()));

    // Append to body so it always exists even when the sidebar is collapsed.
    document.body.appendChild(btn);
  }

  function init() {
    ensureButton();
    setCollapsed(initialCollapsed());
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
