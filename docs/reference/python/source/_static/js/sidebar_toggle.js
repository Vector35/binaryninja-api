// Collapsible navigation sidebar for the API docs.
(() => {
	const KEY = "bn_api_sidebar_collapsed";
	const CLS = "bn-sidebar-collapsed";
	const root = document.documentElement;
	// Collapse is desktop only; on mobile the theme's hamburger owns the nav.
	const desktop = window.matchMedia("(min-width: 769px)");

	const save = (v) => { try { localStorage.setItem(KEY, v); } catch (e) {} };
	const load = () => { try { return localStorage.getItem(KEY); } catch (e) { return null; } };

	let collapsed = load() === "1";

	// Apply saved state before first paint to avoid a layout flash.
	root.classList.toggle(CLS, collapsed);

	const sync = () => {
		const btn = document.getElementById("bn-sidebar-toggle");
		const nav = document.querySelector(".wy-nav-side");
		// Only hide the nav from AT when it is actually offscreen.
		const hidden = collapsed && desktop.matches;
		if (btn) {
			btn.setAttribute("aria-pressed", collapsed ? "true" : "false");
			btn.title = collapsed ? "Show navigation" : "Hide navigation";
		}
		if (nav) {
			if (hidden) {
				nav.setAttribute("aria-hidden", "true");
				nav.setAttribute("inert", "");
			} else {
				nav.removeAttribute("aria-hidden");
				nav.removeAttribute("inert");
			}
		}
	};

	const setCollapsed = (v) => {
		collapsed = v;
		root.classList.toggle(CLS, collapsed);
		save(collapsed ? "1" : "0");
		sync();
	};

	const addButton = () => {
		const nav = document.querySelector(".wy-nav-side");
		if (nav && !nav.id) nav.id = "bn-nav-side";

		const btn = document.createElement("button");
		btn.id = "bn-sidebar-toggle";
		btn.type = "button";
		btn.setAttribute("aria-label", "Toggle navigation");
		if (nav) btn.setAttribute("aria-controls", nav.id);
		btn.textContent = "☰";
		btn.addEventListener("click", () => setCollapsed(!collapsed));
		document.body.appendChild(btn);
		sync();
	};

	// addListener fallback for older Safari/WebKit without addEventListener.
	if (desktop.addEventListener) desktop.addEventListener("change", sync);
	else desktop.addListener(sync);

	if (document.readyState === "loading") {
		document.addEventListener("DOMContentLoaded", addButton);
	} else {
		addButton();
	}
})();
